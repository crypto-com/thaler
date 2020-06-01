use std::{
    collections::VecDeque,
    convert::TryInto,
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
    vec::IntoIter,
};

use async_zmq::{request, Message, MultipartIter, Request};
use futures::ready;
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    sync::Mutex,
};

/// Temporary bridging between the old code and EDP. In the long term, it may go away completely.
///
/// 1. Decryption requests may include the sealed payload in them (so no need to request them via zmq)
/// 2. Encryption requests may be done via a direct attested secure channel (instead of this passing of sealed requests)
pub struct ZmqHelper {
    inner: Mutex<Inner>,
}

/// Inner struct to hold values in a `Mutex`
///
/// `Mutex` is there to enforce the synchronous order as zmq isn't thread safe
struct Inner {
    /// ZeroMQ socket
    socket: Request<IntoIter<Message>, Message>,
    /// State of ZeroMQ socket
    state: SocketState,
    /// Tasks waiting for socket to get ready
    wakers: VecDeque<Waker>,
}

impl ZmqHelper {
    pub fn new(endpoint: &str) -> io::Result<Self> {
        let socket = request(endpoint)
            .map_err(into_io_err)?
            .connect()
            .map_err(into_io_err)?;

        Ok(ZmqHelper {
            inner: Mutex::new(Inner {
                socket,
                state: SocketState::Ready,
                wakers: VecDeque::new(),
            }),
        })
    }
}

impl Inner {
    /// Wakes the next task waiting for ready state (if any)
    fn wake_next(&mut self) {
        if let Some(waker) = self.wakers.pop_front() {
            waker.wake()
        }
    }

    /// Adds task to waiting queue
    fn add_wait(&mut self, waker: Waker) {
        self.wakers.push_back(waker)
    }
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

impl AsyncRead for ZmqHelper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner_future = Box::pin(self.inner.lock());
        let mut inner = ready!(inner_future.as_mut().poll(cx));

        let mut is_request_complete = false;

        let response = match inner.state {
            SocketState::Ready => {
                unreachable!("Unable to receive message. Previous request wasn't sent")
            }
            SocketState::RequestSent => {
                let response = {
                    let mut future = Box::pin(inner.socket.recv());
                    ready!(future.as_mut().poll(cx))
                };
                match response {
                    Ok(multipart) => {
                        // We don't expect multipart messages from ZeroMQ. Assuming only one message
                        assert_eq!(
                            1,
                            multipart.len(),
                            "Received multiple messages in ZeroMQ response"
                        );

                        let response = multipart.into_iter().next().unwrap();
                        let response_len: u32 = response
                            .len()
                            .try_into()
                            .expect("Message length exceeds `u32` bounds");
                        buf.copy_from_slice(&response_len.to_le_bytes());

                        inner.state = SocketState::ResponseReceived(response);

                        Poll::Ready(Ok(std::mem::size_of::<u32>()))
                    }
                    Err(e) => Poll::Ready(Err(into_io_err(e))),
                }
            }
            SocketState::ResponseReceived(ref response) => {
                is_request_complete = true;
                buf.copy_from_slice(&response);
                Poll::Ready(Ok(response.len()))
            }
        };

        if is_request_complete {
            inner.state = SocketState::Ready;
            inner.wake_next();
        }

        response
    }
}

impl AsyncWrite for ZmqHelper {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut inner_future = Box::pin(self.inner.lock());
        let mut inner = ready!(inner_future.as_mut().poll(cx));

        if let SocketState::Ready = inner.state {
            let multipart = MultipartIter(vec![Message::from(buf)].into_iter());

            let response = {
                let mut future = Box::pin(inner.socket.send(multipart));
                ready!(future.as_mut().poll(cx))
            };

            match response {
                Ok(_) => {
                    inner.state = SocketState::RequestSent;
                    Poll::Ready(Ok(buf.len()))
                }
                Err(e) => Poll::Ready(Err(into_io_err(e))),
            }
        } else {
            log::debug!("Unable to send message. Previous response isn't processed");
            inner.add_wait(cx.waker().clone());
            Poll::Pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn into_io_err<E: Into<async_zmq::Error>>(error: E) -> io::Error {
    let error = error.into();

    use std::io::ErrorKind;

    let kind = match error {
        async_zmq::Error::ENOENT => ErrorKind::NotFound,
        async_zmq::Error::EACCES => ErrorKind::PermissionDenied,
        async_zmq::Error::ECONNREFUSED => ErrorKind::ConnectionRefused,
        async_zmq::Error::ENOTCONN => ErrorKind::NotConnected,
        async_zmq::Error::EADDRINUSE => ErrorKind::AddrInUse,
        async_zmq::Error::EADDRNOTAVAIL => ErrorKind::AddrNotAvailable,
        async_zmq::Error::EAGAIN => ErrorKind::WouldBlock,
        async_zmq::Error::EINVAL => ErrorKind::InvalidInput,
        async_zmq::Error::EINTR => ErrorKind::Interrupted,
        _ => ErrorKind::Other,
    };

    kind.into()
}
