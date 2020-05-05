use super::{BufferType, ChainNodeApp, ChainNodeState};
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::{process_public_tx, verify_enclave_tx, TxAction, TxEnclaveAction};
use crate::tx_error::TxError;
use abci::*;
use chain_core::tx::data::TxId;
use chain_core::tx::TxAux;
use chain_storage::buffer::{StoreKV, StoreStaking};
use parity_scale_codec::Decode;

/// Wrapper to abstract over CheckTx and DeliverTx requests
pub trait RequestWithTx {
    fn tx(&self) -> &[u8];
    fn store_valid(&self) -> bool;
}

impl RequestWithTx for RequestCheckTx {
    fn tx(&self) -> &[u8] {
        &self.tx[..]
    }
    fn store_valid(&self) -> bool {
        false
    }
}

impl RequestWithTx for RequestDeliverTx {
    fn tx(&self) -> &[u8] {
        &self.tx[..]
    }
    fn store_valid(&self) -> bool {
        true
    }
}

/// Wrapper to abstract over CheckTx and DeliverTx responses
pub trait ResponseWithCodeAndLog {
    fn set_code(&mut self, _: u32);
    fn add_log(&mut self, _: &str);
}

impl ResponseWithCodeAndLog for ResponseCheckTx {
    fn set_code(&mut self, new_code: u32) {
        self.code = new_code;
    }

    fn add_log(&mut self, entry: &str) {
        self.log += entry;
    }
}

impl ResponseWithCodeAndLog for ResponseDeliverTx {
    fn set_code(&mut self, new_code: u32) {
        self.code = new_code;
    }

    fn add_log(&mut self, entry: &str) {
        self.log += entry;
    }
}

impl<T: EnclaveProxy> ChainNodeApp<T> {
    pub fn process_tx(
        &mut self,
        req: &impl RequestWithTx,
        buffer_type: BufferType,
    ) -> Result<(TxAux, TxAction), TxError> {
        let extra_info = self.tx_extra_info(req.tx().len());
        let state = match buffer_type {
            BufferType::Consensus => self.last_state.as_mut().expect("expect last_state"),
            BufferType::Mempool => self.mempool_state.as_mut().expect("expect mempool_state"),
        };
        let txaux = TxAux::decode(&mut req.tx())?;
        let txid = txaux.tx_id();
        let tx_action = match &txaux {
            TxAux::EnclaveTx(tx) => {
                let action = verify_enclave_tx(
                    &mut self.tx_validator,
                    &tx,
                    &extra_info,
                    &staking_getter!(self, state.staking_version, buffer_type),
                    &kv_store!(self, buffer_type),
                )?;
                // execute the action
                execute_enclave_tx(
                    &mut staking_store!(self, state.staking_version, buffer_type),
                    &mut kv_store!(self, buffer_type),
                    state,
                    &txid,
                    &action,
                );

                // update utxo coins
                match action {
                    TxEnclaveAction::Withdraw {
                        withdraw: (_, coin),
                        fee,
                        ..
                    } => {
                        state.utxo_coins =
                            (state.utxo_coins + (coin - fee.to_coin()).unwrap()).unwrap()
                    }
                    TxEnclaveAction::Deposit {
                        deposit: (_, coin),
                        fee,
                        ..
                    } => {
                        state.utxo_coins =
                            (state.utxo_coins - (coin + fee.to_coin()).unwrap()).unwrap()
                    }
                    TxEnclaveAction::Transfer { fee, .. } => {
                        state.utxo_coins = (state.utxo_coins - fee.to_coin()).unwrap()
                    }
                }

                TxAction::Enclave(action)
            }
            TxAux::PublicTx(tx) => {
                let action = process_public_tx(
                    &mut staking_store!(self, state.staking_version, buffer_type),
                    &mut state.staking_table,
                    &extra_info,
                    &tx,
                )?;

                TxAction::Public(action)
            }
        };
        Ok((txaux, tx_action))
    }
}

fn execute_enclave_tx(
    trie: &mut impl StoreStaking,
    kvdb: &mut impl StoreKV,
    state: &mut ChainNodeState,
    txid: &TxId,
    action: &TxEnclaveAction,
) {
    match action {
        TxEnclaveAction::Transfer {
            spend_utxo,
            sealed_log,
            ..
        } => {
            chain_storage::spend_utxos(kvdb, &spend_utxo);
            // Done in commit event
            // storage.create_utxo(no_of_outputs, txid);
            chain_storage::store_sealed_log(kvdb, &txid, sealed_log);
        }
        TxEnclaveAction::Deposit {
            spend_utxo,
            deposit: (address, amount),
            ..
        } => {
            chain_storage::spend_utxos(kvdb, &spend_utxo);
            state
                .staking_table
                .deposit(trie, address, *amount)
                .expect("deposit sanity check");
        }
        TxEnclaveAction::Withdraw {
            withdraw: (address, amount),
            sealed_log,
            ..
        } => {
            // Done in commit event
            // storage.create_utxo(no_of_outputs, txid);
            chain_storage::store_sealed_log(kvdb, &txid, sealed_log);

            // no panic: tx is already verified, all the error in execution is not allowed.
            // operations are sequential in the state machine, so no concurrent updates
            state
                .staking_table
                .withdraw(trie, state.block_time, address, *amount)
                .expect("withdraw sanity check");
        }
    }
}
