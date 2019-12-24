use sgx_types::{c_int, sgx_status_t, SgxResult};
use tx_query_enclave::run_server;

#[derive(Clone)]
pub struct TxQueryEnclave();

impl TxQueryEnclave {
    pub fn new(_filename: &str, _debug: bool) -> SgxResult<TxQueryEnclave> {
        Ok(TxQueryEnclave())
    }

    pub fn run_server(&self, socket_fd: c_int, timeout: c_int) -> sgx_status_t {
        run_server(socket_fd, timeout)
    }
}
