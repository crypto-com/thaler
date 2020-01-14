#![crate_name = "tx_validation_enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(proc_macro_hygiene)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

mod obfuscate;
mod validate;

use enclave_macro::get_network_id;
use enclave_protocol::IntraEnclaveRequest;
use parity_scale_codec::Decode;
use sgx_types::sgx_status_t;
use std::slice;

pub const NETWORK_HEX_ID: u8 = get_network_id!();

/// FIXME: genesis app_hash etc.
#[no_mangle]
pub extern "C" fn ecall_initchain(chain_hex_id: u8) -> sgx_status_t {
    if chain_hex_id == NETWORK_HEX_ID {
        sgx_status_t::SGX_SUCCESS
    } else {
        log::error!("network hex id not match");
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    }
}

/// # Safety
///
/// This function should not be called with null pointer.
#[no_mangle]
pub unsafe extern "C" fn ecall_check_tx(
    tx_request: *const u8,
    tx_request_len: usize,
    response_buf: *mut u8,
    response_len: u32,
) -> sgx_status_t {
    let mut tx_request_slice = slice::from_raw_parts(tx_request, tx_request_len);
    match IntraEnclaveRequest::decode(&mut tx_request_slice) {
        Ok(IntraEnclaveRequest::ValidateTx { request, tx_inputs }) => {
            validate::handle_validate_tx(request, tx_inputs, response_buf, response_len)
        }
        Ok(IntraEnclaveRequest::EndBlock) => validate::handle_end_block(response_buf, response_len),
        Ok(IntraEnclaveRequest::Encrypt(request)) => {
            obfuscate::handle_encrypt_request(request, response_buf, response_len)
        }
        Err(e) => {
            log::error!("ecall check tx failed: {:?}", e);
            sgx_status_t::SGX_ERROR_INVALID_PARAMETER
        }
    }
}
