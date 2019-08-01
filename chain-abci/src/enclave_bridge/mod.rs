use enclave_protocol::{EnclaveRequest, EnclaveResponse, FLAGS};
use parity_codec::{Decode, Encode};
use std::sync::{Arc, Mutex};
use zmq::Socket;

/// TODO: feature-guard when workspaces can be built with --features flag: https://github.com/rust-lang/cargo/issues/5015
pub mod mock;

/// Abstracts over communication with an external process that does enclave calls
pub trait EnclaveProxy: Sync + Send + Sized {
    fn process_request(&mut self, request: EnclaveRequest) -> EnclaveResponse;
}

/// Provides communication with the enclave wrapper app over ZMQ
/// NOTE / WARNING: this connection is trusted / non-attested
/// (it's assumed Tendermint node, Chain ABCI app and enclave process would run on the same machine)
pub struct ZmqEnclaveClient {
    socket: Arc<Mutex<Socket>>,
}

impl ZmqEnclaveClient {
    pub fn new(socket: Socket) -> Self {
        ZmqEnclaveClient {
            socket: Arc::new(Mutex::new(socket)),
        }
    }
}

impl EnclaveProxy for ZmqEnclaveClient {
    fn process_request(&mut self, request: EnclaveRequest) -> EnclaveResponse {
        let asocket = Arc::clone(&self.socket);
        let socket = asocket.lock().unwrap();
        let req = request.encode();
        socket.send(req, FLAGS).expect("request sending failed");
        let msg = socket
            .recv_bytes(FLAGS)
            .expect("failed to receive a response");
        EnclaveResponse::decode(&mut msg.as_slice()).expect("failed to parse a response")
    }
}
