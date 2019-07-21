#![allow(dead_code)]
///! TODO: feature-guard when workspaces can be built with --features flag: https://github.com/rust-lang/cargo/issues/5015
use super::*;
use chain_core::tx::PlainTxAux;
use chain_core::tx::TxAux;
use chain_core::tx::TxObfuscated;
use chain_tx_validation::{verify_bonded_deposit, verify_transfer, verify_unbonded_withdraw};

pub struct MockClient {
    chain_hex_id: u8,
}

impl MockClient {
    pub fn new(chain_hex_id: u8) -> Self {
        MockClient { chain_hex_id }
    }
}

impl EnclaveProxy for MockClient {
    fn process_request(&self, request: EnclaveRequest) -> EnclaveResponse {
        match request {
            EnclaveRequest::CheckChain { chain_hex_id } => {
                if chain_hex_id == self.chain_hex_id {
                    EnclaveResponse::CheckChain(Ok(()))
                } else {
                    EnclaveResponse::CheckChain(Err(()))
                }
            }
            EnclaveRequest::VerifyTx {
                tx,
                account,
                inputs,
                info,
            } => {
                let txpayload = match &tx {
                    TxAux::TransferTx {
                        payload: TxObfuscated { txpayload, .. },
                        ..
                    } => txpayload,
                    TxAux::DepositStakeTx {
                        payload: TxObfuscated { txpayload, .. },
                        ..
                    } => txpayload,
                    TxAux::WithdrawUnbondedStakeTx {
                        payload: TxObfuscated { txpayload, .. },
                        ..
                    } => txpayload,
                    _ => {
                        return EnclaveResponse::UnsupportedTxType;
                    }
                };
                // FIXME
                let plain_tx = PlainTxAux::decode(&mut txpayload.as_slice());
                // verify_bonded_deposit(maintx, witness, extra_info, input_transactions, account)?
                // verify_unbonded_withdraw(maintx, extra_info, account)?
                match (tx, plain_tx) {
                    (_, Some(PlainTxAux::TransferTx(maintx, witness))) => {
                        let result = verify_transfer(&maintx, &witness, info, inputs);
                        if let Ok(fee) = result {
                            EnclaveResponse::VerifyTx(Ok((fee, account)))
                        } else {
                            EnclaveResponse::VerifyTx(Err(()))
                        }
                    }
                    (
                        TxAux::DepositStakeTx { tx, .. },
                        Some(PlainTxAux::DepositStakeTx(witness)),
                    ) => {
                        let result = verify_bonded_deposit(&tx, &witness, info, inputs, account);
                        EnclaveResponse::VerifyTx(result.map_err(|_| ()))
                    }
                    (_, Some(PlainTxAux::WithdrawUnbondedStakeTx(tx))) => {
                        let result = verify_unbonded_withdraw(
                            &tx,
                            info,
                            account.expect("account exists in withdraw"),
                        );
                        EnclaveResponse::VerifyTx(result.map_err(|_| ()))
                    }

                    _ => EnclaveResponse::UnsupportedTxType,
                }
            }
        }
    }
}
