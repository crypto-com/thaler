use std::{
    convert::TryInto,
    io::{self, Read, Write},
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    prelude::Async,
    sync::lock::Lock,
};
use zmq::{Context, Message, Result, Socket, REQ};

use enclave_protocol::FLAGS;

macro_rules! lock {
    ($e:expr) => {
        match $e.poll_lock() {
            Async::Ready(inner) => inner,
            Async::NotReady => return Ok(Async::NotReady),
        }
    };
}

macro_rules! try_lock {
    ($e:expr) => {
        match $e.poll_lock() {
            Async::Ready(inner) => inner,
            Async::NotReady => return Err(io::ErrorKind::WouldBlock.into()),
        }
    };
}

macro_rules! try_poll {
    ($e:expr) => {
        match $e {
            Async::Ready(inner) => inner,
            Async::NotReady => return Err(io::ErrorKind::WouldBlock.into()),
        }
    };
}

/// Temporary bridging between the old code and EDP. In the long term, it may go away completely.
///
/// 1. Decryption requests may include the sealed payload in them (so no need to request them via zmq)
/// 2. Encryption requests may be done via a direct attested secure channel (instead of this passing of sealed requests)
pub struct ZmqHelper {
    inner: Lock<Inner>,
}

/// Inner struct to hold values in a `Lock`
///
/// `Lock` is there to enforce the synchronous order as zmq isn't thread safe
struct Inner {
    /// State of ZeroMQ socket
    state: SocketState,
    /// ZeroMQ socket
    socket: Socket,
}

/// State of ZeroMQ socket
#[derive(Debug)]
enum SocketState {
    /// Denotes that a new request can be sent on ZeroMQ socket
    Ready,
    /// Denotes that a request is sent to ZeroMQ socket but response is not received yet
    RequestSent,
    /// Denotes that response to a previously sent request is received
    ResponseReceived(Message),
}

impl ZmqHelper {
    /// Creates a new instance of ZeroMQ helper
    pub fn new(connection_str: &str) -> Self {
        let ctx = Context::new();
        let socket = ctx.socket(REQ).expect("failed to init zmq context");
        socket
            .connect(connection_str)
            .expect("failed to connect to the tx validation enclave zmq");

        let inner = Inner {
            state: SocketState::Ready,
            socket,
        };

        log::debug!("Successfully created ZeroMQ helper");

        Self {
            inner: Lock::new(inner),
        }
    }

    /// Sends a message to ZeroMQ socket
    pub fn send<S: Into<Message>>(&mut self, message: S) -> Result<Async<()>> {
        log::debug!("Sending message to ZeroMQ");
        let mut inner = lock!(self.inner);

        match inner.state {
            SocketState::Ready => {
                inner.socket.send(message, FLAGS)?;
                inner.state = SocketState::RequestSent;
                Ok(Async::Ready(()))
            }
            _ => {
                log::debug!("Unable to send message. Previous response isn't processed");
                Ok(Async::NotReady)
            }
        }
    }

    /// Returns `true` if previous request was sent. `false` otherwise.
    pub fn is_request_sent(&mut self) -> Result<Async<bool>> {
        let inner = lock!(self.inner);
        Ok(Async::Ready(matches!(
            inner.state,
            SocketState::RequestSent
        )))
    }

    /// Returns `true` if response was received. `false` otherwise.
    pub fn is_response_received(&mut self) -> Result<Async<bool>> {
        let inner = lock!(self.inner);
        Ok(Async::Ready(matches!(
            inner.state,
            SocketState::ResponseReceived(_)
        )))
    }

    /// Returns the length of message received from ZeroMQ
    pub fn get_message_len(&mut self) -> Result<Async<usize>> {
        let mut inner = lock!(self.inner);

        let message = match inner.state {
            SocketState::RequestSent => inner.socket.recv_msg(FLAGS)?,
            _ => {
                log::debug!("Unable to receive message. Previous request wasn't sent");
                return Ok(Async::NotReady);
            }
        };

        let message_len = message.len();
        inner.state = SocketState::ResponseReceived(message);

        Ok(Async::Ready(message_len))
    }

    /// Returns the message received from ZeroMQ
    pub fn get_message(&mut self) -> Result<Async<Message>> {
        log::debug!("Receiving response to ZeroMQ");
        let mut inner = lock!(self.inner);

        if matches!(inner.state, SocketState::ResponseReceived(_)) {
            let mut socket_state = SocketState::Ready;
            std::mem::swap(&mut socket_state, &mut inner.state);

            if let SocketState::ResponseReceived(message) = socket_state {
                Ok(Async::Ready(message))
            } else {
                unreachable!("Socket state cannot be anything other than `ResponseReceived`")
            }
        } else {
            log::debug!("Unable to receive message. Previous request wasn't sent");
            Ok(Async::NotReady)
        }
    }
}

impl Read for ZmqHelper {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if try_poll!(self.is_request_sent()?) {
            let message_len: u32 = try_poll!(self.get_message_len()?)
                .try_into()
                .expect("Message length exceeds `u32` bounds");

            buf.copy_from_slice(&message_len.to_le_bytes());
            Ok(core::mem::size_of::<u32>())
        } else if try_poll!(self.is_response_received()?) {
            let message = try_poll!(self.get_message()?);
            buf.copy_from_slice(&message);
            Ok(message.len())
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
}

impl Write for ZmqHelper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        try_poll!(self.send(buf)?);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        try_lock!(self.inner);
        Ok(())
    }
}

impl AsyncRead for ZmqHelper {}

impl AsyncWrite for ZmqHelper {
    fn shutdown(&mut self) -> io::Result<Async<()>> {
        Ok(().into())
    }
}
