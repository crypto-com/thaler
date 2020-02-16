use sgx_types::*;

use chain_core::tx::TxObfuscated;
use chain_tx_validation::Error;
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse, IntraEnclaveResponseOk};
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

pub fn check_initchain(eid: sgx_enclave_id_t, chain_hex_id: u8) -> Result<(), ()> {
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { ecall_initchain(eid, &mut retval, chain_hex_id) };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        Ok(())
    } else {
        Err(())
    }
}

pub fn end_block(eid: sgx_enclave_id_t, request: IntraEnclaveRequest) -> IntraEnclaveResponse {
    let request_buf: Vec<u8> = request.encode();
    // Buffer size: Result(1)+Result(1)+Enum(1)+Option(1)+Box(0)+TxFilter(256)
    let mut response_buf: Vec<u8> = vec![0u8; 260];
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let response_slice = &mut response_buf[..];
    let result = unsafe {
        ecall_check_tx(
            eid,
            &mut retval,
            request_buf.as_ptr(),
            request_buf.len(),
            response_slice.as_mut_ptr(),
            response_buf.len() as u32,
        )
    };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        let response = IntraEnclaveResponse::decode(&mut response_buf.as_slice());
        match response {
            Ok(resp) => resp,
            Err(e) => {
                log::error!("endblock response failed: {:?}", e);
                Err(Error::EnclaveRejected)
            }
        }
    } else {
        Err(Error::EnclaveRejected)
    }
}

pub fn encrypt_tx(
    eid: sgx_enclave_id_t,
    request: IntraEnclaveRequest,
) -> Result<TxObfuscated, chain_tx_validation::Error> {
    let request_buf: Vec<u8> = request.encode();
    let mut response_buf: Vec<u8> = vec![0u8; request_buf.len()];
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let response_slice = &mut response_buf[..];
    let result = unsafe {
        ecall_check_tx(
            eid,
            &mut retval,
            request_buf.as_ptr(),
            request_buf.len(),
            response_slice.as_mut_ptr(),
            response_buf.len() as u32,
        )
    };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        let response = IntraEnclaveResponse::decode(&mut response_buf.as_slice());
        match response {
            Ok(Ok(IntraEnclaveResponseOk::Encrypt(obftx))) => Ok(obftx),
            Ok(Ok(_)) => {
                log::error!("encrypt unsupported tx");
                Err(Error::EnclaveRejected)
            }
            Ok(Err(e)) => {
                log::error!("encrypt tx error: {:?}", e);
                Err(Error::EnclaveRejected)
            }
            Err(e) => {
                log::error!("encrypt tx response failed: {:?}", e);
                Err(Error::EnclaveRejected)
            }
        }
    } else {
        log::error!(
            "sgx status error: retval: {:?}, ecall result: {:?}",
            retval,
            result
        );
        Err(Error::EnclaveRejected)
    }
}

pub fn check_tx(eid: sgx_enclave_id_t, request: IntraEnclaveRequest) -> IntraEnclaveResponse {
    let request_buf: Vec<u8> = request.encode();
    let response_len = size_of::<sgx_sealed_data_t>() + request_buf.len();
    let mut response_buf: Vec<u8> = vec![0u8; response_len];
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let response_slice = &mut response_buf[..];
    let result = unsafe {
        ecall_check_tx(
            eid,
            &mut retval,
            request_buf.as_ptr(),
            request_buf.len(),
            response_slice.as_mut_ptr(),
            response_buf.len() as u32,
        )
    };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        let response = IntraEnclaveResponse::decode(&mut response_buf.as_slice());
        match response {
            Ok(resp) => resp,
            Err(e) => {
                log::error!("check tx response failed: {:?}", e);
                Err(Error::EnclaveRejected)
            }
        }
    } else {
        log::error!(
            "sgx status error: retval: {:?}, ecall result: {:?}",
            retval,
            result
        );
        Err(Error::EnclaveRejected)
    }
}
