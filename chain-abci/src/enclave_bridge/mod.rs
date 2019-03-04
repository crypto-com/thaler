use abci_enclave_protocol::{read_bincode, send_bincode, SubAbciRequest, SubAbciResponse};
use std::net::TcpStream;

pub trait EnclaveProxy: Sync + Send + Sized {
    fn process_request(&mut self, request: SubAbciRequest) -> SubAbciResponse;
}

pub struct TcpEnclaveClient {
    stream: TcpStream,
}

impl TcpEnclaveClient {
    pub fn new(stream: TcpStream) -> Self {
        TcpEnclaveClient { stream }
    }
}

impl EnclaveProxy for TcpEnclaveClient {
    fn process_request(&mut self, request: SubAbciRequest) -> SubAbciResponse {
        send_bincode(&request, &mut self.stream).expect("failed to send a request");
        let resp: Option<SubAbciResponse> = read_bincode(&mut self.stream);
        resp.expect("failed to read a response")
    }
}
