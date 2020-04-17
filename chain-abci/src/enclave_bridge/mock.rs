#![allow(dead_code)]
///! TODO: feature-guard when workspaces can be built with --features flag: https://github.com/rust-lang/cargo/issues/5015
use super::*;
use chain_core::state::account::DepositBondTx;
use chain_core::tx::PlainTxAux;
use chain_core::tx::TxEnclaveAux;
use chain_core::tx::TxObfuscated;
use chain_core::tx::TxWithOutputs;
use chain_tx_filter::BlockFilter;
use chain_tx_validation::{verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw};
use enclave_protocol::IntraEnclaveResponseOk;

pub struct MockClient {
    chain_hex_id: u8,
    filter: BlockFilter,
}

impl MockClient {
    pub fn new(chain_hex_id: u8) -> Self {
        MockClient {
            chain_hex_id,
            filter: BlockFilter::default(),
        }
    }

    fn add_view_keys(&mut self, plain_tx: &TxWithOutputs) {
        match plain_tx {
            TxWithOutputs::StakeWithdraw(tx) => {
                for view in tx.attributes.allowed_view.iter() {
                    self.filter.add_view_key(&view.view_key);
                }
            }
            TxWithOutputs::Transfer(tx) => {
                for view in tx.attributes.allowed_view.iter() {
                    self.filter.add_view_key(&view.view_key);
                }
            }
        }
    }
}

impl EnclaveProxy for MockClient {
    fn check_chain(&self, network_id: u8) -> Result<(), ()> {
        if self.chain_hex_id == network_id {
            Ok(())
        } else {
            Err(())
        }
    }

    fn process_request(&mut self, request: IntraEnclaveRequest) -> IntraEnclaveResponse {
        match &request {
            IntraEnclaveRequest::EndBlock => {
                let maybe_filter = if self.filter.is_modified() {
                    Some(Box::new(self.filter.get_raw()))
                } else {
                    None
                };
                self.filter.reset();
                Ok(IntraEnclaveResponseOk::EndBlock(maybe_filter))
            }
            IntraEnclaveRequest::Encrypt(_) => {
                // TODO: mock / simulate ?
                Err(chain_tx_validation::Error::EnclaveRejected)
            }
            IntraEnclaveRequest::ValidateTx { request, tx_inputs } => {
                let (tx, account, info) =
                    (request.tx.clone(), request.account.clone(), request.info);

                let (txpayload, inputs) = match (&tx, tx_inputs) {
                    (
                        TxEnclaveAux::TransferTx {
                            payload: TxObfuscated { txpayload, .. },
                            ..
                        },
                        Some(inputs),
                    ) => (
                        txpayload,
                        inputs
                            .iter()
                            .map(|x| TxWithOutputs::decode(&mut x.as_slice()).expect("TODO mock"))
                            .collect(),
                    ),
                    (
                        TxEnclaveAux::DepositStakeTx {
                            tx: DepositBondTx { .. },
                            payload: TxObfuscated { txpayload, .. },
                            ..
                        },
                        Some(inputs),
                    ) => (
                        txpayload,
                        inputs
                            .iter()
                            .map(|x| TxWithOutputs::decode(&mut x.as_slice()).expect("TODO mock"))
                            .collect(),
                    ),
                    (
                        TxEnclaveAux::WithdrawUnbondedStakeTx {
                            payload: TxObfuscated { txpayload, .. },
                            ..
                        },
                        _,
                    ) => (txpayload, vec![]),
                    _ => unreachable!(),
                };
                // FIXME
                let plain_tx = PlainTxAux::decode(&mut txpayload.as_slice());
                match (tx, plain_tx) {
                    (
                        TxEnclaveAux::TransferTx { .. },
                        Ok(PlainTxAux::TransferTx(maintx, witness)),
                    ) => {
                        let result = verify_transfer(&maintx, &witness, &info, inputs);
                        match result {
                            Ok(fee) => {
                                let txwo = TxWithOutputs::Transfer(maintx);
                                self.add_view_keys(&txwo);

                                Ok(IntraEnclaveResponseOk::TxWithOutputs {
                                    paid_fee: fee,
                                    sealed_tx: txwo.encode(),
                                })
                            }
                            Err(e) => Err(e),
                        }
                    }
                    (
                        TxEnclaveAux::DepositStakeTx { tx, .. },
                        Ok(PlainTxAux::DepositStakeTx(witness)),
                    ) => {
                        let result = verify_bonded_deposit_core(&tx, &witness, &info, inputs);
                        match result {
                            Ok(input_coins) => {
                                Ok(IntraEnclaveResponseOk::DepositStakeTx { input_coins })
                            }
                            Err(e) => Err(e),
                        }
                    }
                    (
                        TxEnclaveAux::WithdrawUnbondedStakeTx { .. },
                        Ok(PlainTxAux::WithdrawUnbondedStakeTx(tx)),
                    ) => {
                        let fee = verify_unbonded_withdraw(
                            &tx,
                            &info,
                            &account.expect("account exists in withdraw"),
                        )?;
                        let txwo = TxWithOutputs::StakeWithdraw(tx);
                        self.add_view_keys(&txwo);

                        Ok(IntraEnclaveResponseOk::TxWithOutputs {
                            paid_fee: fee,
                            sealed_tx: txwo.encode(),
                        })
                    }
                    _ => Err(chain_tx_validation::Error::EnclaveRejected),
                }
            }
        }
    }
}
