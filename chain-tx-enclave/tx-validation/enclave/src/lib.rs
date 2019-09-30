#![crate_name = "txvalidationenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(proc_macro_hygiene)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use chain_core::init::coin::Coin;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_core::tx::TransactionId;
use chain_core::tx::{data::input::TxoIndex, PlainTxAux, TxAux, TxObfuscated};
use chain_tx_filter::BlockFilter;
use chain_tx_validation::witness::verify_tx_recover_address;
use chain_tx_validation::{
    verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw_core, TxWithOutputs,
};
use enclave_macro::get_network_id;
use enclave_protocol::{
    is_basic_valid_tx_request, IntraEnclaveRequest, IntraEnclaveResponse, IntraEnclaveResponseOk,
    VerifyTxRequest,
};
use enclave_t_common::check_unseal;
use lazy_static::lazy_static;
use parity_scale_codec::{Decode, Encode};
use sgx_tseal::SgxSealedData;
use sgx_types::{sgx_sealed_data_t, sgx_status_t};
use std::prelude::v1::{Box, Vec};
use std::slice;
use std::sync::SgxMutex;

lazy_static! {
    static ref FILTER: SgxMutex<BlockFilter> = SgxMutex::new(BlockFilter::default());
}

const NETWORK_HEX_ID: u8 = get_network_id!();

/// FIXME: genesis app_hash etc.
#[no_mangle]
pub extern "C" fn ecall_initchain(chain_hex_id: u8) -> sgx_status_t {
    if chain_hex_id == NETWORK_HEX_ID {
        sgx_status_t::SGX_SUCCESS
    } else {
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    }
}

#[inline]
fn add_view_keys(wraptx: &TxWithOutputs) {
    let mut filter = FILTER
        .lock()
        .expect("poisoned lock: failed to get block tx filter");
    match wraptx {
        TxWithOutputs::Transfer(tx) => {
            for view in tx.attributes.allowed_view.iter() {
                filter.add_view_key(&view.view_key);
            }
        }
        TxWithOutputs::StakeWithdraw(tx) => {
            for view in tx.attributes.allowed_view.iter() {
                filter.add_view_key(&view.view_key);
            }
        }
    }
}

#[inline]
fn construct_sealed_response(
    result: Result<Fee, chain_tx_validation::Error>,
    txid: &TxId,
    to_seal_tx: TxWithOutputs,
) -> Result<IntraEnclaveResponse, sgx_status_t> {
    let to_seal = to_seal_tx.encode();
    match result {
        Err(e) => Ok(Err(e)),
        Ok(fee) => {
            let sealing_result = SgxSealedData::<[u8]>::seal_data(txid, &to_seal);
            let sealed_data = match sealing_result {
                Ok(x) => x,
                Err(ret) => {
                    return Err(ret);
                }
            };
            let sealed_log_size = SgxSealedData::<[u8]>::calc_raw_sealed_data_size(
                sealed_data.get_add_mac_txt_len(),
                sealed_data.get_encrypt_txt_len(),
            ) as usize;
            let mut sealed_log: Vec<u8> = vec![0u8; sealed_log_size];

            unsafe {
                let sealed_r = sealed_data.to_raw_sealed_data_t(
                    sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t,
                    sealed_log_size as u32,
                );
                if sealed_r.is_none() {
                    return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
                }
            }
            add_view_keys(&to_seal_tx);
            Ok(Ok(IntraEnclaveResponseOk::TxWithOutputs {
                paid_fee: fee,
                sealed_tx: sealed_log,
            }))
        }
    }
}

#[inline]
fn construct_simple_response(
    result: Result<Coin, chain_tx_validation::Error>,
) -> Result<IntraEnclaveResponse, sgx_status_t> {
    match result {
        Err(e) => Ok(Err(e)),
        Ok(input_coins) => Ok(Ok(IntraEnclaveResponseOk::DepositStakeTx { input_coins })),
    }
}

#[inline]
fn write_back_response(
    response: Result<IntraEnclaveResponse, sgx_status_t>,
    response_buf: *mut u8,
    max_response_len: u32,
) -> sgx_status_t {
    match response {
        Ok(r) => {
            let to_copy = r.encode();
            let resp_len = to_copy.len() as u32;
            if resp_len > 0 && resp_len <= max_response_len {
                unsafe {
                    std::ptr::copy_nonoverlapping(to_copy.as_ptr(), response_buf, to_copy.len());
                }
                sgx_status_t::SGX_SUCCESS
            } else {
                sgx_status_t::SGX_ERROR_INVALID_PARAMETER
            }
        }
        Err(e) => e,
    }
}

#[inline]
fn handle_validate_tx(
    request: Box<VerifyTxRequest>,
    tx_inputs: Option<Vec<Vec<u8>>>,
    response_buf: *mut u8,
    response_len: u32,
) -> sgx_status_t {
    if is_basic_valid_tx_request(&request, &tx_inputs, NETWORK_HEX_ID).is_err() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    match (tx_inputs, request.tx) {
        (
            Some(sealed_inputs),
            TxAux::TransferTx {
                txid,
                payload: TxObfuscated { txpayload, .. },
                no_of_outputs,
                inputs,
            },
        ) => {
            // FIXME: decrypting
            let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
            let unsealed_inputs =
                check_unseal(None, false, inputs.iter().map(|x| x.id), sealed_inputs);
            match (plaintx, unsealed_inputs) {
                (Ok(PlainTxAux::TransferTx(tx, witness)), Some(inputs)) => {
                    if tx.id() != txid || tx.outputs.len() as TxoIndex != no_of_outputs {
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                    }
                    let result = verify_transfer(&tx, &witness, request.info, inputs);
                    let response =
                        construct_sealed_response(result, &txid, TxWithOutputs::Transfer(tx));
                    write_back_response(response, response_buf, response_len)
                }
                _ => {
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
            }
        }
        (
            Some(sealed_inputs),
            TxAux::DepositStakeTx {
                tx,
                payload: TxObfuscated { txpayload, .. },
            },
        ) => {
            // FIXME: decrypting
            let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
            let inputs = check_unseal(None, false, tx.inputs.iter().map(|x| x.id), sealed_inputs);
            match (plaintx, inputs) {
                (Ok(PlainTxAux::DepositStakeTx(witness)), Some(inputs)) => {
                    let result = verify_bonded_deposit_core(&tx, &witness, request.info, inputs);
                    let response = construct_simple_response(result);
                    write_back_response(response, response_buf, response_len)
                }
                _ => {
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
            }
        }
        (
            None,
            TxAux::WithdrawUnbondedStakeTx {
                txid,
                no_of_outputs,
                payload: TxObfuscated { txpayload, .. },
                witness,
            },
        ) => {
            let address = verify_tx_recover_address(&witness, &txid);
            if address.is_err() {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
            // FIXME: decrypting
            let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
            match (plaintx, request.account) {
                (Ok(PlainTxAux::WithdrawUnbondedStakeTx(tx)), Some(account)) => {
                    if tx.id() != txid
                        || no_of_outputs != tx.outputs.len() as TxoIndex
                        || account.address != address.unwrap()
                    {
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                    }
                    let result = verify_unbonded_withdraw_core(&tx, request.info, &account);
                    let response =
                        construct_sealed_response(result, &txid, TxWithOutputs::StakeWithdraw(tx));
                    write_back_response(response, response_buf, response_len)
                }
                _ => {
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
            }
        }
        (_, _) => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }
}

#[no_mangle]
pub extern "C" fn ecall_check_tx(
    tx_request: *const u8,
    tx_request_len: usize,
    response_buf: *mut u8,
    response_len: u32,
) -> sgx_status_t {
    let mut tx_request_slice = unsafe { slice::from_raw_parts(tx_request, tx_request_len) };
    match IntraEnclaveRequest::decode(&mut tx_request_slice) {
        Ok(IntraEnclaveRequest::ValidateTx { request, tx_inputs }) => {
            handle_validate_tx(request, tx_inputs, response_buf, response_len)
        }
        Ok(IntraEnclaveRequest::EndBlock) => {
            let mut filter = FILTER
                .lock()
                .expect("poisoned lock: failed to get block tx filter");
            let payload: [u8; 256] = filter.get_raw();
            filter.reset();
            write_back_response(
                Ok(Ok(IntraEnclaveResponseOk::EndBlock(Box::new(payload)))),
                response_buf,
                response_len,
            )
        }
        _ => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }
}
