use sgx_types::*;
use sgx_urts::SgxEnclave;

use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse};
use enclave_u_common::enclave_u::init_enclave;
use parity_scale_codec::{Decode, Encode};
use std::mem::size_of;

extern "C" {
    fn ecall_initchain(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        chain_hex_id: u8,
    ) -> sgx_status_t;

    fn ecall_check_tx(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        tx_request: *const u8,
        tx_request_len: usize,
        response_buf: *mut u8,
        response_len: u32,
    ) -> sgx_status_t;
}

#[derive(Clone)]
pub struct TxValidationEnclave(SgxEnclave);

impl TxValidationEnclave {
    pub fn new(filename: &str, debug: bool) -> SgxResult<TxValidationEnclave> {
        init_enclave(filename, debug).map(TxValidationEnclave)
    }

    pub fn ecall_initchain(&self, chain_hex_id: u8) -> sgx_status_t {
        let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
        unsafe { ecall_initchain(self.0.geteid(), &mut retval, chain_hex_id) }
    }

    pub fn ecall_check_tx(
        &self,
        request: &IntraEnclaveRequest,
    ) -> Result<IntraEnclaveResponse, sgx_status_t> {
        let request_buf: Vec<u8> = request.encode();
        let response_len = size_of::<sgx_sealed_data_t>() + request_buf.len();
        let mut response_buf: Vec<u8> = vec![0u8; response_len];
        let response_slice = &mut response_buf[..];
        let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
        let result = unsafe {
            ecall_check_tx(
                self.0.geteid(),
                &mut retval,
                request_buf.as_ptr(),
                request_buf.len(),
                response_slice.as_mut_ptr(),
                response_buf.len() as u32,
            )
        };
        if retval == sgx_status_t::SGX_SUCCESS && result == retval {
            IntraEnclaveResponse::decode(&mut response_buf.as_slice())
                .map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)
        } else {
            Err(retval)
        }
    }
}
