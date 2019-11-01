#![allow(dead_code)]
///! TODO: feature-guard when workspaces can be built with --features flag: https://github.com/rust-lang/cargo/issues/5015
use super::*;
use crate::storage::Storage;
use crate::storage::COL_BODIES;
use abci::{RequestQuery, ResponseQuery};
use chain_core::state::account::DepositBondTx;
use chain_core::tx::data::input::TxoIndex;
use chain_core::tx::data::TxId;
use chain_core::tx::PlainTxAux;
use chain_core::tx::TransactionId;
use chain_core::tx::TxEnclaveAux;
use chain_core::tx::TxObfuscated;
use chain_core::tx::TxWithOutputs;
use chain_tx_filter::BlockFilter;
use chain_tx_validation::{verify_bonded_deposit, verify_transfer, verify_unbonded_withdraw};
use enclave_protocol::{
    DecryptionRequest, DecryptionRequestBody, DecryptionResponse, EncryptionRequest,
    EncryptionResponse,
};
use log::warn;
use std::collections::HashMap;

/// TODO: Remove
#[cfg(not(feature = "mock-enc-dec"))]
pub fn handle_enc_dec(_req: &RequestQuery, resp: &mut ResponseQuery, storage: &Storage) {
    let msg = "received a temporary *mock* (non-enclave) encryption/decryption query in abci (use the dedicated enclaves instead)";
    warn!(msg);
    resp.log += msg;
    resp.code = 1;
}

/// temporary mock
#[cfg(feature = "mock-enc-dec")]
pub fn handle_enc_dec(_req: &RequestQuery, resp: &mut ResponseQuery, storage: &Storage) {
    warn!("received a temporary *mock* (non-enclave) encryption/decryption query in abci");
    match _req.path.as_ref() {
        // FIXME: temporary mock
        "mockencrypt" => {
            let request = EncryptionRequest::decode(&mut _req.data.as_slice());
            match request {
                Ok(EncryptionRequest::TransferTx(tx, witness)) => {
                    let plain = PlainTxAux::TransferTx(tx.clone(), witness);
                    let mock = EncryptionResponse {
                        tx: TxEnclaveAux::TransferTx {
                            inputs: tx.inputs.clone(),
                            no_of_outputs: tx.outputs.len() as TxoIndex,
                            payload: TxObfuscated {
                                key_from: 0,
                                txid: tx.id(),
                                init_vector: [0u8; 12],
                                txpayload: plain.encode(),
                            },
                        },
                    };
                    resp.value = mock.encode();
                }
                Ok(EncryptionRequest::DepositStake(maintx, witness)) => {
                    let plain = PlainTxAux::DepositStakeTx(witness);
                    let mock = EncryptionResponse {
                        tx: TxEnclaveAux::DepositStakeTx {
                            tx: maintx.clone(),
                            payload: TxObfuscated {
                                key_from: 0,
                                txid: maintx.id(),
                                init_vector: [0u8; 12],
                                txpayload: plain.encode(),
                            },
                        },
                    };
                    resp.value = mock.encode();
                }
                Ok(EncryptionRequest::WithdrawStake(tx, _, witness)) => {
                    let plain = PlainTxAux::WithdrawUnbondedStakeTx(tx.clone());
                    let mock = EncryptionResponse {
                        tx: TxEnclaveAux::WithdrawUnbondedStakeTx {
                            no_of_outputs: tx.outputs.len() as TxoIndex,
                            witness,
                            payload: TxObfuscated {
                                key_from: 0,
                                txid: tx.id(),
                                init_vector: [0u8; 12],
                                txpayload: plain.encode(),
                            },
                        },
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
                let looked_up = txs.iter().map(|txid| storage.db.get(COL_BODIES, txid));
                for found in looked_up {
                    if let Ok(Some(uv)) = found {
                        let tx = TxWithOutputs::decode(&mut uv.to_vec().as_slice());
                        if let Ok(ttx) = tx {
                            resp_txs.push(ttx);
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
    pub local_tx_store: HashMap<TxId, TxWithOutputs>,
    filter: BlockFilter,
}

impl MockClient {
    pub fn new(chain_hex_id: u8) -> Self {
        MockClient {
            chain_hex_id,
            local_tx_store: HashMap::new(),
            filter: BlockFilter::default(),
        }
    }

    fn lookup(&self, txid: &TxId) -> TxWithOutputs {
        let tx = self
            .local_tx_store
            .get(txid)
            .expect("mock is expected to be fed valid/existing TX");
        (*tx).clone()
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
    fn process_request(&mut self, request: EnclaveRequest) -> EnclaveResponse {
        match request {
            EnclaveRequest::CheckChain { chain_hex_id, .. } => {
                if chain_hex_id == self.chain_hex_id {
                    EnclaveResponse::CheckChain(Ok(()))
                } else {
                    EnclaveResponse::CheckChain(Err(None))
                }
            }
            EnclaveRequest::EndBlock => {
                let raw = self.filter.get_raw();
                self.filter.reset();
                EnclaveResponse::EndBlock(Ok(Box::new(raw)))
            }
            EnclaveRequest::CommitBlock { .. } => EnclaveResponse::CommitBlock(Ok(())),
            EnclaveRequest::VerifyTx(txrequest) => {
                let (tx, account, info) = (txrequest.tx, txrequest.account, txrequest.info);
                let (txpayload, inputs) = match &tx {
                    TxEnclaveAux::TransferTx {
                        inputs,
                        payload: TxObfuscated { txpayload, .. },
                        ..
                    } => (
                        txpayload,
                        inputs.iter().map(|x| self.lookup(&x.id)).collect(),
                    ),
                    TxEnclaveAux::DepositStakeTx {
                        tx: DepositBondTx { inputs, .. },
                        payload: TxObfuscated { txpayload, .. },
                        ..
                    } => (
                        txpayload,
                        inputs.iter().map(|x| self.lookup(&x.id)).collect(),
                    ),
                    TxEnclaveAux::WithdrawUnbondedStakeTx {
                        payload: TxObfuscated { txpayload, .. },
                        ..
                    } => (txpayload, vec![]),
                };
                // FIXME
                let plain_tx = PlainTxAux::decode(&mut txpayload.as_slice());
                match (tx, plain_tx) {
                    (_, Ok(PlainTxAux::TransferTx(maintx, witness))) => {
                        let result = verify_transfer(&maintx, &witness, info, inputs);
                        if result.is_ok() {
                            let txid = maintx.id();
                            let txwo = TxWithOutputs::Transfer(maintx);
                            self.add_view_keys(&txwo);
                            self.local_tx_store.insert(txid, txwo);
                        }
                        EnclaveResponse::VerifyTx(result.map(|x| (x, None)))
                    }
                    (
                        TxEnclaveAux::DepositStakeTx { tx, .. },
                        Ok(PlainTxAux::DepositStakeTx(witness)),
                    ) => {
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
                            let txid = tx.id();
                            let txwo = TxWithOutputs::StakeWithdraw(tx);
                            self.add_view_keys(&txwo);
                            self.local_tx_store.insert(txid, txwo);
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
