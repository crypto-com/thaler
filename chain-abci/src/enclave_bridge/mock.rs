#![allow(dead_code)]
///! TODO: feature-guard when workspaces can be built with --features flag: https://github.com/rust-lang/cargo/issues/5015
use super::*;
use chain_core::state::account::DepositBondTx;
use chain_core::tx::data::TxId;
use chain_core::tx::PlainTxAux;
use chain_core::tx::TransactionId;
use chain_core::tx::TxAux;
use chain_core::tx::TxObfuscated;
use chain_core::tx::TxWithOutputs;
use chain_tx_validation::{verify_bonded_deposit, verify_transfer, verify_unbonded_withdraw};
use std::collections::HashMap;

pub struct MockClient {
    chain_hex_id: u8,
    pub local_tx_store: HashMap<TxId, TxWithOutputs>,
}

impl MockClient {
    pub fn new(chain_hex_id: u8) -> Self {
        MockClient {
            chain_hex_id,
            local_tx_store: HashMap::new(),
        }
    }

    fn lookup(&self, txid: &TxId) -> TxWithOutputs {
        let tx = self
            .local_tx_store
            .get(txid)
            .expect("mock is expected to be fed valid/existing TX");
        (*tx).clone()
    }
}

impl EnclaveProxy for MockClient {
    fn process_request(&mut self, request: EnclaveRequest) -> EnclaveResponse {
        match request {
            EnclaveRequest::CheckChain { chain_hex_id, .. } => {
                if chain_hex_id == self.chain_hex_id {
                    EnclaveResponse::CheckChain(Ok(()))
                } else {
                    EnclaveResponse::CheckChain(Err(None))
                }
            }
            EnclaveRequest::CommitBlock { .. } => EnclaveResponse::CommitBlock(Ok(())),
            EnclaveRequest::VerifyTx(txrequest) => {
                let (tx, account, info) = (txrequest.tx, txrequest.account, txrequest.info);
                let (txpayload, inputs) = match &tx {
                    TxAux::TransferTx {
                        inputs,
                        payload: TxObfuscated { txpayload, .. },
                        ..
                    } => (
                        txpayload,
                        inputs.iter().map(|x| self.lookup(&x.id)).collect(),
                    ),
                    TxAux::DepositStakeTx {
                        tx: DepositBondTx { inputs, .. },
                        payload: TxObfuscated { txpayload, .. },
                        ..
                    } => (
                        txpayload,
                        inputs.iter().map(|x| self.lookup(&x.id)).collect(),
                    ),
                    TxAux::WithdrawUnbondedStakeTx {
                        payload: TxObfuscated { txpayload, .. },
                        ..
                    } => (txpayload, vec![]),
                    _ => {
                        return EnclaveResponse::UnsupportedTxType;
                    }
                };
                // FIXME
                let plain_tx = PlainTxAux::decode(&mut txpayload.as_slice());
                // verify_bonded_deposit(maintx, witness, extra_info, input_transactions, account)?
                // verify_unbonded_withdraw(maintx, extra_info, account)?
                match (tx, plain_tx) {
                    (_, Ok(PlainTxAux::TransferTx(maintx, witness))) => {
                        let result = verify_transfer(&maintx, &witness, info, inputs);
                        if result.is_ok() {
                            self.local_tx_store
                                .insert(maintx.id(), TxWithOutputs::Transfer(maintx));
                        }
                        EnclaveResponse::VerifyTx(result.map(|x| (x, None)))
                    }
                    (TxAux::DepositStakeTx { tx, .. }, Ok(PlainTxAux::DepositStakeTx(witness))) => {
                        let result = verify_bonded_deposit(&tx, &witness, info, inputs, account);
                        EnclaveResponse::VerifyTx(result)
                    }
                    (_, Ok(PlainTxAux::WithdrawUnbondedStakeTx(tx))) => {
                        let result = verify_unbonded_withdraw(
                            &tx,
                            info,
                            account.expect("account exists in withdraw"),
                        );
                        if result.is_ok() {
                            self.local_tx_store
                                .insert(tx.id(), TxWithOutputs::StakeWithdraw(tx));
                        }
                        EnclaveResponse::VerifyTx(result)
                    }
                    _ => EnclaveResponse::UnknownRequest,
                }
            }
            _ => EnclaveResponse::UnknownRequest,
        }
    }
}
