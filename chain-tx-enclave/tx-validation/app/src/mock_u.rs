use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse};
use parity_scale_codec::{Decode, Encode};
use sgx_types::{sgx_sealed_data_t, sgx_status_t, SgxResult};
use tx_validation_enclave::{ecall_check_tx, ecall_initchain};

#[derive(Clone)]
pub struct TxValidationEnclave();

impl TxValidationEnclave {
    pub fn new(_filename: &str, _debug: bool) -> SgxResult<TxValidationEnclave> {
        Ok(TxValidationEnclave())
    }

    pub fn ecall_initchain(&self, chain_hex_id: u8) -> sgx_status_t {
        ecall_initchain(chain_hex_id)
    }

    pub fn ecall_check_tx(
        &self,
        request: &IntraEnclaveRequest,
    ) -> Result<IntraEnclaveResponse, sgx_status_t> {
        let request_buf: Vec<u8> = request.encode();
        let response_len = std::mem::size_of::<sgx_sealed_data_t>() + request_buf.len();
        let mut response_buf: Vec<u8> = vec![0u8; response_len];
        let response_slice = &mut response_buf[..];

        let retval = unsafe {
            ecall_check_tx(
                request_buf.as_ptr(),
                request_buf.len(),
                response_slice.as_mut_ptr(),
                response_buf.len() as u32,
            )
        };
        if retval == sgx_status_t::SGX_SUCCESS {
            IntraEnclaveResponse::decode(&mut response_buf.as_slice())
                .map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)
        } else {
            Err(retval)
        }
    }
}
