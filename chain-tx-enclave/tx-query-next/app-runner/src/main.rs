use aesm_client::AesmClient;
use enclave_protocol::FLAGS;
use enclave_runner::usercalls::{AsyncStream, UsercallExtension};
use enclave_runner::EnclaveBuilder;
use futures::future::{Future, FutureExt};
use log::{debug, error, info, trace};
use sgxs_loaders::isgx::Device as IsgxDevice;
use std::env;
use std::io::{Read, Result, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::prelude::Async;
use tokio::sync::lock::Lock;
use zmq::{Context, Socket, REQ};

/// temporary bridging between the old code and EDP
/// in the long term, it may go away completely:
/// 1) decryption requests may include the sealed payload in them (so no need to request them via zmq)
/// 2) encryption requests may be done via a direct attested secure channel (instead of this passing of sealed requests)
struct ZmqStreamHelper {
    /// lock is there to enforce the synchronous order (tokio async stuff tasks?) + thread-safety (zmq isn't thread safe)
    /// Vec<u8> -- buffer for writing/reading the response
    /// AtomicBool -- a flag to denote whether the last message was read/processed
    /// Socket -- zmq socket
    ///
    /// TODO: could this break with multiple enclave threads?
    /// TODO: could there be deadlocks (enclave code "writes", but never "reads" for one request)?
    socket: Lock<(Vec<u8>, AtomicBool, Socket)>,
}

impl ZmqStreamHelper {
    pub fn new(connection_str: &str) -> Self {
        let ctx = Context::new();
        let socket = ctx.socket(REQ).expect("failed to init zmq context");
        socket
            .connect(connection_str)
            .expect("failed to connect to the tx validation enclave zmq");
        Self {
            socket: Lock::new((Vec::new(), AtomicBool::new(true), socket)),
        }
    }
}

impl Read for ZmqStreamHelper {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        debug!("enclave runner: read");
        match self.socket.poll_lock() {
            Async::NotReady => {
                trace!("read no ready");
                Err(std::io::ErrorKind::WouldBlock.into())
            }
            Async::Ready(mut lg) => {
                let next_msg = lg.1.load(Ordering::Relaxed);
                if next_msg {
                    debug!("enclave runner: new message not written yet");
                    Err(std::io::ErrorKind::WouldBlock.into())
                } else {
                    let n = Read::read(&mut lg.0.as_slice(), buf)?;
                    *lg.1.get_mut() = true;
                    Ok(n)
                }
            }
        }
    }
}

impl Write for ZmqStreamHelper {
    /// for some reason "flush" doesn't get called
    /// so this assumes the whole zmq request is in buf
    /// and sends it immediately and waits for reply
    /// (instead of the expected semantics:
    ///  1) write or perhaps multiple writes -- save in temp buffer,
    ///  2) flush -- send to zmq server,
    ///  3) read reply)
    ///
    /// TODO: does this local synchronous REQ-REP zmq exchange break any async stuff?
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        debug!("enclave helper: write");
        match self.socket.poll_lock() {
            Async::NotReady => {
                trace!("write no ready");
                Err(std::io::ErrorKind::WouldBlock.into())
            }
            Async::Ready(mut lg) => {
                let next_msg = lg.1.load(Ordering::Relaxed);
                if next_msg {
                    debug!("enclave runner: send to zmq");
                    lg.2.send(buf, FLAGS)?;

                    debug!("enclave runner: receiving from zmq");
                    let msg = lg.2.recv_bytes(FLAGS)?;
                    debug!("enclave runner: received from zmq");
                    lg.0.clear();
                    lg.0.extend(msg);
                    *lg.1.get_mut() = false;

                    Ok(buf.len())
                } else {
                    debug!("enclave runner: previous message not read yet");
                    Err(std::io::ErrorKind::WouldBlock.into())
                }
            }
        }
    }

    fn flush(&mut self) -> Result<()> {
        // for some reason, even with explicit "flush" call in enclave on that zmq stream, this didn't get called
        debug!("enclave helper: flush");
        match self.socket.poll_lock() {
            Async::NotReady => {
                trace!("flush not ready");
                Err(std::io::ErrorKind::WouldBlock.into())
            }
            Async::Ready(_) => Ok(()),
        }
    }
}

impl AsyncRead for ZmqStreamHelper {}

impl AsyncWrite for ZmqStreamHelper {
    fn shutdown(&mut self) -> tokio::prelude::Poll<(), std::io::Error> {
        Ok(().into())
    }
}

#[derive(Debug)]
struct ZmqService {
    pub connection_str: String,
}

impl UsercallExtension for ZmqService {
    /// the original example had a return type -> Result<Option<Box<dyn AsyncStream>>>
    /// but in nightly-2020-03-18, I get this error:
    /// expected enum `std::result::Result<std::option::Option<std::boxed::Box<(dyn enclave_runner::usercalls::AsyncStream + 'static)>>, std::io::Error>`
    /// found struct `std::pin::Pin<std::boxed::Box<dyn core::future::future::Future<Output = std::result::Result<std::option::Option<std::boxed::Box<dyn enclave_runner::usercalls::AsyncStream>>, _>>>>`
    ///
    fn connect_stream<'a>(
        &'a self,
        addr: &'a str,
        _local_addr: Option<&'a mut String>,
        _peer_addr: Option<&'a mut String>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Box<dyn AsyncStream>>>> + 'a>> {
        async move {
            match &*addr {
                "zmq" => {
                    info!("enclave helper: connecting to zmq");
                    let stream = ZmqStreamHelper::new(&self.connection_str);
                    let boxed_stream: Box<dyn AsyncStream> = Box::new(stream);
                    let option: Option<Box<dyn AsyncStream>> = Some(boxed_stream);
                    Ok(option)
                }
                _ => Ok(None),
            }
        }
        .boxed_local()
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        error!("Please provide: <ENCLAVE_PATH> <ZMQ_CONN_STR>
        ENCLAVE_PATH: the path to *.sgxs file (note signature file be with it)
        ZMQ_CONN_STR: the ZMQ connection string (e.g. \"ipc://enclave.ipc\" or \"tcp://127.0.0.1:25933\") of the tx-validation server (now in chain-abci)
        ");
        std::process::exit(1);
    }
    let mut device = IsgxDevice::new()
        .expect("sgx device was not found")
        .einittoken_provider(AesmClient::new())
        .build();
    let mut enclave_builder = EnclaveBuilder::new(args[1].as_ref());
    // can use `enclave_builder.dummy_signature()` in testing
    enclave_builder
        .coresident_signature()
        .expect("enclave signature file not found");
    enclave_builder.usercall_extension(ZmqService {
        connection_str: args[2].clone(),
    });
    let enclave = enclave_builder
        .build(&mut device)
        .expect("failed to build an enclave");
    enclave.run().expect("failed to start an enclave");
}
