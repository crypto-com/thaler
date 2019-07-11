#![allow(dead_code)]
///! TODO: feature-guard when workspaces can be built with --features flag: https://github.com/rust-lang/cargo/issues/5015
use super::*;
use chain_core::tx::PlainTxAux;
use chain_core::tx::TxAux;
use chain_tx_validation::{verify_transfer, ChainInfo};

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
                tx: TxAux::TransferTx { txpayload, .. },
                inputs,
                min_fee_computed,
                previous_block_time,
                unbonding_period,
            } => {
                // FIXME
                let plain_tx = PlainTxAux::decode(&mut txpayload.as_slice());
                match plain_tx {
                    Some(PlainTxAux::TransferTx(maintx, witness)) => {
                        let info = ChainInfo {
                            min_fee_computed,
                            chain_hex_id: self.chain_hex_id,
                            previous_block_time,
                            unbonding_period,
                        };
                        let result = verify_transfer(&maintx, &witness, info, inputs);
                        if let Ok(fee) = result {
                            EnclaveResponse::VerifyTx(Ok(fee))
                        } else {
                            EnclaveResponse::VerifyTx(Err(()))
                        }
                    }
                    _ => EnclaveResponse::UnsupportedTxType,
                }
            }
            _ => EnclaveResponse::UnsupportedTxType,
        }
    }
}
