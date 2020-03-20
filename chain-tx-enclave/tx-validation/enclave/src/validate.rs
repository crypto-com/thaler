use chain_core::init::coin::Coin;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_core::tx::TransactionId;
use chain_core::tx::{data::input::TxoIndex, PlainTxAux, TxEnclaveAux, TxObfuscated};
use chain_tx_filter::BlockFilter;
use chain_tx_validation::witness::verify_tx_recover_address;
use chain_tx_validation::{
    verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw_core, TxWithOutputs,
};
use enclave_protocol::{
    is_basic_valid_tx_request, IntraEnclaveResponse, IntraEnclaveResponseOk, VerifyTxRequest,
};
use enclave_t_common::check_unseal;
use lazy_static::lazy_static;
use parity_scale_codec::Encode;
use sgx_tseal::SgxSealedData;
use sgx_types::{sgx_sealed_data_t, sgx_status_t};
use std::prelude::v1::{Box, Vec};
use std::sync::SgxMutex;

lazy_static! {
    static ref FILTER: SgxMutex<BlockFilter> = SgxMutex::new(BlockFilter::default());
}

#[inline]
pub(crate) fn handle_end_block(response_buf: *mut u8, response_len: u32) -> sgx_status_t {
    let mut filter = FILTER
        .lock()
        .expect("poisoned lock: failed to get block tx filter");
    let maybe_filter = if filter.is_modified() {
        Some(Box::new(filter.get_raw()))
    } else {
        None
    };
    filter.reset();
    write_back_response(
        Ok(Ok(IntraEnclaveResponseOk::EndBlock(maybe_filter))),
        response_buf,
        response_len,
    )
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
                    log::error!("sgx failed to seal data: {:?}", ret);
                    return Err(ret);
                }
            };
            let sealed_log_size = SgxSealedData::<[u8]>::calc_raw_sealed_data_size(
                sealed_data.get_add_mac_txt_len(),
                sealed_data.get_encrypt_txt_len(),
            ) as usize;
            let mut sealed_log: Vec<u8> = vec![0u8; sealed_log_size];

            unsafe {
                // TODO check alignment correctness
                #[allow(clippy::cast_ptr_alignment)]
                let sealed_r = sealed_data.to_raw_sealed_data_t(
                    sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t,
                    sealed_log_size as u32,
                );
                if sealed_r.is_none() {
                    log::error!("decode sealed data to raw failed");
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

/// writes back the result (if no enclave error happened)
#[inline]
pub(crate) fn write_back_response(
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
                log::error!("response length exceeds the limit");
                sgx_status_t::SGX_ERROR_INVALID_PARAMETER
            }
        }
        Err(e) => e,
    }
}

#[inline]
fn decrypt(payload: &TxObfuscated) -> Result<PlainTxAux, ()> {
    crate::obfuscate::decrypt(payload)
}

/// takes a request to verify transaction and writes back the result
#[inline]
pub(crate) fn handle_validate_tx(
    request: Box<VerifyTxRequest>,
    tx_inputs: Option<Vec<Vec<u8>>>,
    response_buf: *mut u8,
    response_len: u32,
) -> sgx_status_t {
    if let Err(e) = is_basic_valid_tx_request(&request, &tx_inputs, crate::NETWORK_HEX_ID) {
        log::error!("check request failed: {}", e);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    match (tx_inputs, request.tx) {
        (
            Some(sealed_inputs),
            TxEnclaveAux::TransferTx {
                payload,
                no_of_outputs,
                inputs,
            },
        ) => {
            let plaintx = decrypt(&payload);
            let unsealed_inputs =
                check_unseal(None, false, inputs.iter().map(|x| x.id), sealed_inputs);
            match (plaintx, unsealed_inputs) {
                (Ok(PlainTxAux::TransferTx(tx, witness)), Some(inputs)) => {
                    if tx.id() != payload.txid || tx.outputs.len() as TxoIndex != no_of_outputs {
                        log::error!("input invalid txid or outputs index not match!");
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                    }
                    let result = verify_transfer(&tx, &witness, &request.info, inputs);
                    let response = construct_sealed_response(
                        result,
                        &payload.txid,
                        TxWithOutputs::Transfer(tx),
                    );
                    write_back_response(response, response_buf, response_len)
                }
                _ => {
                    log::error!("can not find plain transfer transaction or unsealed inputs");
                    sgx_status_t::SGX_ERROR_INVALID_PARAMETER
                }
            }
        }
        (Some(sealed_inputs), TxEnclaveAux::DepositStakeTx { tx, payload }) => {
            let plaintx = decrypt(&payload);
            let inputs = check_unseal(None, false, tx.inputs.iter().map(|x| x.id), sealed_inputs);
            match (plaintx, inputs) {
                (Ok(PlainTxAux::DepositStakeTx(witness)), Some(inputs)) => {
                    let result = verify_bonded_deposit_core(&tx, &witness, &request.info, inputs);
                    let response = construct_simple_response(result);
                    write_back_response(response, response_buf, response_len)
                }
                _ => {
                    log::error!("can not get plain deposit stake transaction or unsealed inputs");
                    sgx_status_t::SGX_ERROR_INVALID_PARAMETER
                }
            }
        }
        (
            None,
            TxEnclaveAux::WithdrawUnbondedStakeTx {
                no_of_outputs,
                payload,
                witness,
            },
        ) => {
            let address = verify_tx_recover_address(&witness, &payload.txid);
            if let Err(e) = address {
                log::error!("get recover address failed: {:?}", e);
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
            let plaintx = decrypt(&payload);
            match (plaintx, request.account) {
                (Ok(PlainTxAux::WithdrawUnbondedStakeTx(tx)), Some(account)) => {
                    if tx.id() != payload.txid
                        || no_of_outputs != tx.outputs.len() as TxoIndex
                        || account.address != address.unwrap()
                    {
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                    }
                    let result = verify_unbonded_withdraw_core(&tx, &request.info, &account);
                    let response = construct_sealed_response(
                        result,
                        &payload.txid,
                        TxWithOutputs::StakeWithdraw(tx),
                    );
                    write_back_response(response, response_buf, response_len)
                }
                _ => {
                    log::error!("invalid parameter");
                    sgx_status_t::SGX_ERROR_INVALID_PARAMETER
                }
            }
        }
        (_, _) => {
            log::error!("invalid parameter");
            sgx_status_t::SGX_ERROR_INVALID_PARAMETER
        }
    }
}
