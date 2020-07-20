mod server;

use crate::enclave_bridge::EnclaveProxy;
use aesm_client::AesmClient;
use chain_storage::ReadOnlyStorage;
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse};
use enclave_runner::{
    usercalls::{AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use parity_scale_codec::{Decode, Encode};
use sgxs_loaders::isgx::Device;
use std::io::{Cursor, Read};
use std::sync::{mpsc::channel, mpsc::Receiver, mpsc::Sender, Arc, Mutex};
use std::thread::{self};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// Internal type for communicating with EDP-based tx-validation enclave
#[derive(Debug)]
pub struct TxValidationStream {
    /// contains the serialize request
    reader: Cursor<Vec<u8>>,
    /// for replying back with the response
    request_processed: Sender<IntraEnclaveResponse>,
}

impl TxValidationStream {
    /// start with a channel to send back responses
    pub fn new(request_processed: Sender<IntraEnclaveResponse>) -> Self {
        Self {
            reader: Default::default(),
            request_processed,
        }
    }

    /// only 1 at a time can push the request (locked outside)
    pub fn push_request(&mut self, request: IntraEnclaveRequest) {
        let avail = self.reader.get_ref().len();
        if self.reader.position() == avail as u64 {
            self.reader = Default::default();
        }
        self.reader.get_mut().extend(&request.encode());
    }
}

/// multi-thread wrapper around `TxValidationStream`.
/// Currently, at least 3 threads are accessing it:
/// 1) chain-abci main thread (pushing requests when check/delivertx)
/// 2) zmq server -- temporarily -- pushes requests received from tx-query
/// 3) enclave runner -- passes requests/responses via async streams
/// from/to tx-validation enclave
#[derive(Debug, Clone)]
pub struct TxValidationAsyncStream {
    stream: Arc<Mutex<TxValidationStream>>,
}

impl TxValidationAsyncStream {
    pub fn new(request_processed: Sender<IntraEnclaveResponse>) -> Self {
        Self {
            stream: Arc::new(Mutex::new(TxValidationStream::new(request_processed))),
        }
    }
}

impl AsyncRead for TxValidationAsyncStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // the locking should not block for too long -- this either succeeds and goes through
        // or wait for `TxValidationApp` to push the request (it releases the lock
        // once it pushes it)
        let mut stream = self.stream.lock().expect("lock for stream -- async read");
        let r = stream.reader.read(buf);
        Poll::Ready(r)
    }
}

impl AsyncWrite for TxValidationAsyncStream {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        // the locking should not block --
        // at the moment, tx-validation enclave shouldn't
        // be executed on several threads and `TxValidationApp` won't hold the lock
        // as it releases it and waits for `send` here
        let stream = self.stream.lock().expect("lock for stream -- async write");
        let resp = IntraEnclaveResponse::decode(&mut buf.as_ref())
            .expect("enclave writes valid responses");
        if let Err(e) = stream.request_processed.send(resp) {
            log::warn!("receiver dropped: {:?}", e);
            Poll::Ready(Err(std::io::ErrorKind::Other.into()))
        } else {
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Clone)]
pub struct TxValidationApp {
    inner: TxValidationAsyncStream,
    rx: Arc<Mutex<Receiver<IntraEnclaveResponse>>>,
}

impl Default for TxValidationApp {
    fn default() -> Self {
        let (tx, rx) = channel();
        TxValidationApp {
            inner: TxValidationAsyncStream::new(tx),
            rx: Arc::new(Mutex::new(rx)),
        }
    }
}

/// It launches a ZMQ server that can server tx-query requests;
/// (used to be in a separate process -- tx-validation-app that had a custom storage;
/// now it's in a thread of chain-abci and shares its storage)
pub fn start_zmq<T: EnclaveProxy + 'static>(
    proxy: T,
    zmq_conn_str: &str,
    network_id: u8,
    storage: ReadOnlyStorage,
) -> thread::JoinHandle<()> {
    let (sender, receiver) = channel();
    let mut server =
        server::TxValidationServer::new(zmq_conn_str, proxy, storage, network_id, sender)
            .expect("could not start a zmq server");
    log::info!("starting zmq server");
    let child_t = thread::spawn(move || server.execute());
    receiver.recv().unwrap();
    child_t
}

type UserCallStream = io::Result<Option<Box<dyn AsyncStream>>>;

impl UsercallExtension for TxValidationApp {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = UserCallStream> + 'future>> {
        async fn connect_stream_inner(
            stream: TxValidationAsyncStream,
            addr: &str,
        ) -> UserCallStream {
            match addr {
                "chain-abci" => Ok(Some(Box::new(stream))),
                _ => Ok(None),
            }
        }

        Box::pin(connect_stream_inner(self.inner.clone(), addr))
    }
}

impl EnclaveProxy for TxValidationApp {
    fn check_chain(&mut self, network_id: u8) -> Result<(), ()> {
        self.process_request(IntraEnclaveRequest::InitChainCheck(network_id))
            .map(|_| ())
            .map_err(|_| ())
    }

    fn process_request(&mut self, request: IntraEnclaveRequest) -> IntraEnclaveResponse {
        // this lock prevents zmq server + chain-abci to submit requests at the same time
        // as the zmq is temporary, this can later be removed
        // (and perhaps use some channel that implements both Sync + Send, unlike mpsc)
        let rx = self.rx.lock().expect("lock for reply");
        {
            let mut stream = self.inner.stream.lock().expect("lock for stream -- proxy");
            stream.push_request(request);
            // release the lock for `UsercallExtension` processing in async streams
            // the explicit drop should not be necessary, but here just for sanity
            drop(stream);
        }
        match rx.recv() {
            Ok(response) => response,
            Err(e) => {
                log::warn!("the sender dropped {:?}", e);
                Err(chain_tx_validation::Error::EnclaveRejected)
            }
        }
    }
}

/// Launches tx-validation enclave --
/// it expects "tx-validation-next.sgxs" (+ signature)
/// to be in the same directory as chain-abci
pub fn launch_tx_validation() -> TxValidationApp {
    let app = TxValidationApp::default();
    let app2 = app.clone();
    let mut device = Device::new()
        .expect("SGX device was not found")
        .einittoken_provider(AesmClient::new())
        .build();
    let enclave_path = "tx-validation-next.sgxs";
    let mut enclave_builder = EnclaveBuilder::new(enclave_path.as_ref());
    enclave_builder
        .coresident_signature()
        .expect("Enclave signature file not found");

    enclave_builder.usercall_extension(app);
    let enclave = enclave_builder
        .build(&mut device)
        .expect("Failed to build enclave");
    thread::spawn(|| {
        log::info!("starting tx validation enclave");
        enclave.run().expect("Failed to start enclave")
    });
    app2
}
