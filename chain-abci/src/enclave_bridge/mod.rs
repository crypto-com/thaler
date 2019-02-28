use abci_enclave_protocol::{SubAbciRequest, SubAbciResponse, FLAGS};
use zmq::{Socket, Context, REP, Error};
use bincode::{serialize, deserialize};
use std::sync::{Arc, Mutex};

pub trait EnclaveProxy: Sync + Send + Sized {
    fn process_request(&self, request: SubAbciRequest) -> SubAbciResponse;
}

pub struct ZmqEnclaveClient {
    socket: Arc<Mutex<Socket>>
}

impl ZmqEnclaveClient {
    pub fn new(socket: Socket) -> Self {
        ZmqEnclaveClient {
            socket: Arc::new(Mutex::new(socket))
        }
    }
}

impl EnclaveProxy for ZmqEnclaveClient {
    fn process_request(&self, request: SubAbciRequest) -> SubAbciResponse {
        let asocket = Arc::clone(&self.socket);
        let socket = asocket.lock().unwrap();
        let req = serialize(&request).expect("serialized valid request");
        socket.send(req, FLAGS).expect("request sending failed");
        let msg = socket.recv_bytes(FLAGS).expect("failed to receive a response");
        let resp: SubAbciResponse = deserialize(&msg[..]).expect("failed to parse a response");
        resp
    }
}