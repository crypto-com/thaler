#![allow(dead_code)]
///! TODO: feature-guard when workspaces can be built with --features flag: https://github.com/rust-lang/cargo/issues/5015
use super::*;
use abci::{RequestQuery, ResponseQuery};
use chain_core::state::account::DepositBondTx;
#[cfg(feature = "mock-enc-dec")]
use chain_core::state::tendermint::BlockHeight;
#[cfg(feature = "mock-enc-dec")]
use chain_core::tx::data::input::TxoSize;
use chain_core::tx::PlainTxAux;
#[cfg(feature = "mock-enc-dec")]
use chain_core::tx::TransactionId;
use chain_core::tx::TxEnclaveAux;
use chain_core::tx::TxObfuscated;
use chain_core::tx::TxWithOutputs;
use chain_storage::Storage;
use chain_tx_filter::BlockFilter;
use chain_tx_validation::{verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw};
use enclave_protocol::IntraEnclaveResponseOk;
#[cfg(feature = "mock-enc-dec")]
use enclave_protocol::{
    DecryptionRequest, DecryptionRequestBody, DecryptionResponse, EncryptionRequest,
    EncryptionResponse,
};
use log::warn;

/// TODO: Remove
#[cfg(not(feature = "mock-enc-dec"))]
pub fn handle_enc_dec(_req: &RequestQuery, resp: &mut ResponseQuery, _storage: &Storage) {
    let msg = "received a temporary *mock* (non-enclave) encryption/decryption query in abci (use the dedicated enclaves instead)";
    warn!("{}", msg);
    resp.log += msg;
    resp.code = 1;
}

fn pad_payload(payload: &[u8]) -> Vec<u8> {
    // https://tools.ietf.org/html/rfc8452
    let mut result = Vec::with_capacity(payload.len() + 16);
    result.extend_from_slice(payload);
    result.extend_from_slice(&[0; 16]);
    result
}

/// temporary mock
#[cfg(feature = "mock-enc-dec")]
pub fn handle_enc_dec(_req: &RequestQuery, resp: &mut ResponseQuery, storage: &Storage) {
    warn!(
        "{}",
        "received a temporary *mock* (non-enclave) encryption/decryption query in abci"
    );
    match _req.path.as_ref() {
        // FIXME: temporary mock
        "mockencrypt" => {
            let request = EncryptionRequest::decode(&mut _req.data.as_slice());
            match request {
                Ok(EncryptionRequest::TransferTx(tx, witness)) => {
                    let plain = PlainTxAux::TransferTx(tx.clone(), witness);
                    let mock = EncryptionResponse {
                        resp: Ok(TxEnclaveAux::TransferTx {
                            inputs: tx.inputs.clone(),
                            no_of_outputs: tx.outputs.len() as TxoSize,
                            payload: TxObfuscated {
                                key_from: BlockHeight::genesis(),
                                txid: tx.id(),
                                init_vector: [0u8; 12],
                                txpayload: pad_payload(&plain.encode()),
                            },
                        }),
                    };
                    resp.value = mock.encode();
                }
                Ok(EncryptionRequest::DepositStake(maintx, witness)) => {
                    let plain = PlainTxAux::DepositStakeTx(witness);
                    let mock = EncryptionResponse {
                        resp: Ok(TxEnclaveAux::DepositStakeTx {
                            tx: maintx.clone(),
                            payload: TxObfuscated {
                                key_from: BlockHeight::genesis(),
                                txid: maintx.id(),
                                init_vector: [0u8; 12],
                                txpayload: pad_payload(&plain.encode()),
                            },
                        }),
                    };
                    resp.value = mock.encode();
                }
                Ok(EncryptionRequest::WithdrawStake(tx, _, witness)) => {
                    let plain = PlainTxAux::WithdrawUnbondedStakeTx(tx.clone());
                    let mock = EncryptionResponse {
                        resp: Ok(TxEnclaveAux::WithdrawUnbondedStakeTx {
                            no_of_outputs: tx.outputs.len() as TxoSize,
                            witness,
                            payload: TxObfuscated {
                                key_from: BlockHeight::genesis(),
                                txid: tx.id(),
                                init_vector: [0u8; 12],
                                txpayload: pad_payload(&plain.encode()),
                            },
                        }),
                    };
                    resp.value = mock.encode();
                }
                _ => {
                    resp.log += "invalid request";
                    resp.code = 1;
                }
            }
        }
        // FIXME: temporary mock
        "mockdecrypt" => {
            let request = DecryptionRequest::decode(&mut _req.data.as_slice());
            if let Ok(DecryptionRequest {
                body: DecryptionRequestBody { txs, .. },
                ..
            }) = request
            {
                let mut resp_txs = Vec::with_capacity(txs.len());
                let looked_up = txs.iter().map(|txid| storage.get_sealed_log(txid));
                for found in looked_up {
                    if let Some(uv) = found {
                        if let Ok(tx) = TxWithOutputs::decode(&mut uv.to_vec().as_slice()) {
                            resp_txs.push(tx);
                        }
                    }
                }
                let mock = DecryptionResponse { txs: resp_txs };
                resp.value = mock.encode();
            } else {
                resp.log += "invalid request";
                resp.code = 1;
            }
        }
        _ => {
            resp.log += "invalid path";
            resp.code = 1;
        }
    }
}

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
                        let result = verify_unbonded_withdraw(
                            &tx,
                            &info,
                            account.expect("account exists in withdraw"),
                        );
                        match result {
                            Ok((fee, _account)) => {
                                let txwo = TxWithOutputs::StakeWithdraw(tx);
                                self.add_view_keys(&txwo);

                                Ok(IntraEnclaveResponseOk::TxWithOutputs {
                                    paid_fee: fee,
                                    sealed_tx: txwo.encode(),
                                })
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => Err(chain_tx_validation::Error::EnclaveRejected),
                }
            }
        }
    }
}
