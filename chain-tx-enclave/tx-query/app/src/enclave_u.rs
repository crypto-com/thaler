use enclave_u_common::enclave_u::init_enclave;
use sgx_types::*;
use sgx_urts::SgxEnclave;

extern "C" {
    /// the enclave main function / routine (just gets raw file descriptor of the connection client TCP socket)
    pub fn run_server(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        socket_fd: c_int,
        timeout: c_int,
    ) -> sgx_status_t;
}

#[derive(Clone)]
pub struct TxQueryEnclave(SgxEnclave);

impl TxQueryEnclave {
    pub fn new(filename: &str, debug: bool) -> SgxResult<TxQueryEnclave> {
        init_enclave(filename, debug).map(TxQueryEnclave)
    }

    pub fn run_server(&self, socket_fd: c_int, timeout: c_int) -> sgx_status_t {
        let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
        unsafe { run_server(self.0.geteid(), &mut retval, socket_fd, timeout) }
    }
}
