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
use sgx_types::sgx_status_t;
use sgx_wrapper::{Box, Mutex, SealedData, Vec};

lazy_static! {
    static ref FILTER: Mutex<BlockFilter> = Mutex::new(BlockFilter::default());
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
            let sealing_result = SealedData::seal_data(txid, &to_seal);
            let sealed_data = match sealing_result {
                Ok(x) => x,
                Err(ret) => {
                    return Err(ret);
                }
            };
            let sealed_log = match sealed_data.to_bytes() {
                Some(bytes) => bytes,
                None => {
                    return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
                }
            };

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
    if is_basic_valid_tx_request(&request, &tx_inputs, *crate::NETWORK_HEX_ID).is_err() {
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
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                    }
                    let result = verify_transfer(&tx, &witness, request.info, inputs);
                    let response = construct_sealed_response(
                        result,
                        &payload.txid,
                        TxWithOutputs::Transfer(tx),
                    );
                    write_back_response(response, response_buf, response_len)
                }
                _ => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
            }
        }
        (Some(sealed_inputs), TxEnclaveAux::DepositStakeTx { tx, payload }) => {
            let plaintx = decrypt(&payload);
            let inputs = check_unseal(None, false, tx.inputs.iter().map(|x| x.id), sealed_inputs);
            match (plaintx, inputs) {
                (Ok(PlainTxAux::DepositStakeTx(witness)), Some(inputs)) => {
                    let result = verify_bonded_deposit_core(&tx, &witness, request.info, inputs);
                    let response = construct_simple_response(result);
                    write_back_response(response, response_buf, response_len)
                }
                _ => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
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
            if address.is_err() {
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
                    let result = verify_unbonded_withdraw_core(&tx, request.info, &account);
                    let response = construct_sealed_response(
                        result,
                        &payload.txid,
                        TxWithOutputs::StakeWithdraw(tx),
                    );
                    write_back_response(response, response_buf, response_len)
                }
                _ => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
            }
        }
        (_, _) => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    }
}
