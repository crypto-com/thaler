use crate::sgx_module::obfuscate::check_unseal;
use crate::sgx_module::write_response;
use chain_core::init::coin::Coin;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_core::tx::TransactionId;
use chain_core::tx::{data::input::TxoSize, PlainTxAux, TxEnclaveAux, TxObfuscated};
use chain_tx_filter::BlockFilter;
use chain_tx_validation::witness::verify_tx_recover_address;
use chain_tx_validation::Error;
use chain_tx_validation::{
    verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw_core, TxWithOutputs,
};
use enclave_protocol::{
    is_basic_valid_tx_request, IntraEnclaveResponse, IntraEnclaveResponseOk, VerifyTxRequest,
};
use enclave_utils::SealedData;
use parity_scale_codec::Encode;
use std::io::Write;
use std::prelude::v1::{Box, Vec};

#[inline]
fn add_view_keys(wraptx: &TxWithOutputs, filter: &mut BlockFilter) {
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
    filter: &mut BlockFilter,
) -> IntraEnclaveResponse {
    result.map(|fee| {
        let to_seal = to_seal_tx.encode();
        // TODO: no panic?
        let sealed_log = SealedData::seal(&to_seal, *txid).expect("seal");
        add_view_keys(&to_seal_tx, filter);

        IntraEnclaveResponseOk::TxWithOutputs {
            paid_fee: fee,
            sealed_tx: sealed_log,
        }
    })
}

#[inline]
fn construct_simple_response(
    result: Result<Coin, chain_tx_validation::Error>,
) -> IntraEnclaveResponse {
    result.map(|input_coins| IntraEnclaveResponseOk::DepositStakeTx { input_coins })
}

#[inline]
fn decrypt(payload: &TxObfuscated) -> Result<PlainTxAux, ()> {
    crate::sgx_module::obfuscate::decrypt(payload)
}

/// takes a request to verify transaction and writes back the result
#[inline]
pub(crate) fn handle_validate_tx<I: Write>(
    request: Box<VerifyTxRequest>,
    tx_inputs: Option<Vec<Vec<u8>>>,
    filter: &mut BlockFilter,
    output: &mut I,
) {
    if let Err(e) =
        is_basic_valid_tx_request(&request, &tx_inputs, crate::sgx_module::NETWORK_HEX_ID)
    {
        log::error!("check request failed: {}", e);
    } else {
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
                let unsealed_inputs = check_unseal(inputs.iter().map(|x| x.id), sealed_inputs);
                match (plaintx, unsealed_inputs) {
                    (Ok(PlainTxAux::TransferTx(tx, witness)), Some(inputs)) => {
                        if tx.id() != payload.txid || tx.outputs.len() as TxoSize != no_of_outputs {
                            log::error!("input invalid txid or outputs index not match!");
                        } else {
                            let result = verify_transfer(&tx, &witness, &request.info, inputs);
                            let response = construct_sealed_response(
                                result,
                                &payload.txid,
                                TxWithOutputs::Transfer(tx),
                                filter,
                            );
                            write_response(response, output);
                        }
                    }
                    _ => {
                        log::error!("can not find plain transfer transaction or unsealed inputs");
                        write_response(Err(Error::EnclaveRejected), output);
                    }
                }
            }
            (Some(sealed_inputs), TxEnclaveAux::DepositStakeTx { tx, payload }) => {
                let plaintx = decrypt(&payload);
                let inputs = check_unseal(tx.inputs.iter().map(|x| x.id), sealed_inputs);
                match (plaintx, inputs) {
                    (Ok(PlainTxAux::DepositStakeTx(witness)), Some(inputs)) => {
                        let result =
                            verify_bonded_deposit_core(&tx, &witness, &request.info, inputs);
                        let response = construct_simple_response(result);
                        write_response(response, output);
                    }
                    _ => {
                        log::error!(
                            "can not get plain deposit stake transaction or unsealed inputs"
                        );
                        write_response(Err(Error::EnclaveRejected), output);
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
                    write_response(Err(Error::EnclaveRejected), output);
                } else {
                    let plaintx = decrypt(&payload);
                    match (plaintx, request.account) {
                        (Ok(PlainTxAux::WithdrawUnbondedStakeTx(tx)), Some(account)) => {
                            if tx.id() != payload.txid
                                || no_of_outputs != tx.outputs.len() as TxoSize
                                || account.address != address.unwrap()
                            {
                                log::error!("invalid parameter");
                                write_response(Err(Error::EnclaveRejected), output);
                            } else {
                                let result =
                                    verify_unbonded_withdraw_core(&tx, &request.info, &account);
                                let response = construct_sealed_response(
                                    result,
                                    &payload.txid,
                                    TxWithOutputs::StakeWithdraw(tx),
                                    filter,
                                );
                                write_response(response, output);
                            }
                        }
                        _ => {
                            log::error!("invalid parameter");
                            write_response(Err(Error::EnclaveRejected), output);
                        }
                    }
                }
            }
            (_, _) => {
                log::error!("invalid parameter");
                write_response(Err(Error::EnclaveRejected), output);
            }
        }
    }
}
