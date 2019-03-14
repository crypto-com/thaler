use abci_enclave_protocol::{read_bincode, send_bincode, SubAbciRequest, SubAbciResponse};
use std::net::TcpStream;

pub trait EnclaveProxy: Sync + Send + Sized {
    fn process_request(&mut self, request: SubAbciRequest) -> SubAbciResponse;
}

#[allow(dead_code)]
/// currently only used in app, not lib
pub struct TcpEnclaveClient {
    stream: TcpStream,
}

impl TcpEnclaveClient {
    #[allow(dead_code)]
    /// currently only used in app, not lib
    pub fn new(stream: TcpStream) -> Self {
        // TODO: TLS / Noise
        // TODO: remote attestation
        // currently, it's a bit cumbersome to compile SGX with mbedTLS (requires old version of LLVM)
        // and remote attestation via the `aesm-client` crate is a bit spartan.
        // so while this is essential, it's postponed for the moment.
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
