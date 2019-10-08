use sgx_types::*;

use chain_core::common::H256;
use chain_core::state::account::DepositBondTx;
use chain_core::state::account::StakedState;
use chain_core::tx::fee::Fee;
use chain_core::tx::TxAux;
use chain_core::tx::TxObfuscated;
use chain_tx_validation::Error;
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse, IntraEnclaveResponseOk};
use enclave_u_common::enclave_u::TOKEN_LEN;
use log::{info, warn};
use parity_scale_codec::{Decode, Encode};
use sled::Tree;
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

pub fn get_token(metadb: &Tree, token_key: &[u8]) -> Option<Vec<u8>> {
    match metadb.get(token_key) {
        Ok(x) => x.map(|tok| tok.to_vec()),
        _ => None,
    }
}

pub fn get_token_arr(metadb: &Tree, token_key: &[u8]) -> Result<Option<Box<[u8; TOKEN_LEN]>>, ()> {
    match metadb.get(token_key) {
        Ok(x) => Ok(x.map(|tok| {
            let mut token = [0; TOKEN_LEN];
            token.copy_from_slice(&tok);
            Box::new(token)
        })),
        _ => Err(()),
    }
}

pub fn store_token(metadb: &mut Tree, token_key: &[u8], launch_token: Vec<u8>) -> Result<(), ()> {
    match metadb.insert(token_key, launch_token) {
        Ok(_) => {
            info!("[+] Saved updated launch token!");
            Ok(())
        }
        Err(_) => {
            warn!("[-] Failed to save updated launch token!");
            Err(())
        }
    }
}

pub fn check_initchain(
    eid: sgx_enclave_id_t,
    chain_hex_id: u8,
    last_app_hash: Option<H256>,
) -> Result<(), Option<H256>> {
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { ecall_initchain(eid, &mut retval, chain_hex_id) };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        Ok(())
    } else {
        Err(last_app_hash)
    }
}

pub fn end_block(
    eid: sgx_enclave_id_t,
    request: IntraEnclaveRequest,
) -> Result<Box<[u8; 256]>, ()> {
    let request_buf: Vec<u8> = request.encode();
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
            Ok(Ok(IntraEnclaveResponseOk::EndBlock(filter))) => Ok(filter),
            _ => Err(()),
        }
    } else {
        Err(())
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
            Ok(Err(e)) => Err(e),
            _ => Err(Error::EnclaveRejected),
        }
    } else {
        Err(Error::EnclaveRejected)
    }
}

pub fn check_tx(
    eid: sgx_enclave_id_t,
    request: IntraEnclaveRequest,
    txdb: &mut Tree,
) -> Result<(Fee, Option<StakedState>), Error> {
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
        match (request, response) {
            (
                IntraEnclaveRequest::ValidateTx { request, .. },
                Ok(Ok(IntraEnclaveResponseOk::TxWithOutputs {
                    paid_fee,
                    sealed_tx,
                })),
            ) => {
                let _ = txdb
                    .insert(&request.tx.tx_id(), sealed_tx)
                    .map_err(|_| Error::IoError)?;
                if let Some(mut account) = request.account {
                    account.withdraw();
                    Ok((paid_fee, Some(account)))
                } else {
                    Ok((paid_fee, None))
                }
            }
            (
                IntraEnclaveRequest::ValidateTx { request, .. },
                Ok(Ok(IntraEnclaveResponseOk::DepositStakeTx { input_coins })),
            ) => {
                let deposit_amount =
                    (input_coins - request.info.min_fee_computed.to_coin()).expect("init");
                let account = match (request.account, request.tx) {
                    (Some(mut a), _) => {
                        a.deposit(deposit_amount);
                        Some(a)
                    }
                    (
                        None,
                        TxAux::DepositStakeTx {
                            tx:
                                DepositBondTx {
                                    to_staked_account, ..
                                },
                            ..
                        },
                    ) => Some(StakedState::new_init(
                        deposit_amount,
                        request.info.previous_block_time,
                        to_staked_account,
                        true,
                    )),
                    (_, _) => unreachable!("one shouldn't call this with other variants"),
                };
                let fee = request.info.min_fee_computed;
                Ok((fee, account))
            }
            (_, Ok(Err(e))) => Err(e),
            (_, _) => Err(Error::EnclaveRejected),
        }
    } else {
        Err(Error::EnclaveRejected)
    }
}
