use super::ChainNodeApp;
use crate::app::spend_utxos;
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::*;
use abci::*;
use bit_vec::BitVec;
use chain_core::common::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::tx::data::input::{TxoIndex, TxoPointer};
use chain_core::tx::data::TxId;
use chain_core::tx::PlainTxAux;
use chain_core::tx::TxObfuscated;
use chain_core::tx::{TxAux, TxEnclaveAux};
use chain_core::ChainInfo;
use chain_tx_validation::TxWithOutputs;
use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use integer_encoding::VarInt;
use kvdb::{DBTransaction, KeyValueDB};
use log::debug;
use parity_scale_codec::{Decode, Encode};
use std::sync::Arc;

/// Given a db and a DB transaction, it will go through TX inputs and mark them as spent
/// in the TX_META storage and it will create a new entry for TX in TX_META with all outputs marked as unspent.
pub fn update_utxos_commit(
    inputs: &[TxoPointer],
    no_of_outputs: TxoIndex,
    txid: TxId,
    db: Arc<dyn KeyValueDB>,
    dbtx: &mut DBTransaction,
) {
    spend_utxos(inputs, db, dbtx);
    dbtx.put(
        COL_TX_META,
        &txid,
        &BitVec::from_elem(no_of_outputs as usize, false).to_bytes(),
    );
}

impl<T: EnclaveProxy> ChainNodeApp<T> {
    pub fn process_txs(&mut self, inittx: &mut DBTransaction) {
        for txaux in self.delivered_txs.iter() {
            let txid: TxId = txaux.tx_id();
            // TODO: do the abci-query mock via enclave mock + switch to tx-query in client by default
            // TODO: some of the storage may be unnecessary / duplicate
            match &txaux {
                TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
                    inputs,
                    no_of_outputs,
                    payload: TxObfuscated { txpayload, .. },
                    ..
                }) => {
                    // FIXME: temporary hack / this shouldn't be here
                    let plain_tx = PlainTxAux::decode(&mut txpayload.as_slice());
                    if let Ok(PlainTxAux::TransferTx(tx, witness)) = plain_tx {
                        inittx.put(
                            COL_BODIES,
                            &txid[..],
                            &TxWithOutputs::Transfer(tx.clone()).encode(),
                        );
                        inittx.put(COL_WITNESS, &txid[..], &witness.encode());
                    }
                    update_utxos_commit(
                        &inputs,
                        *no_of_outputs,
                        txid,
                        self.storage.db.clone(),
                        inittx,
                    );
                }
                TxAux::EnclaveTx(TxEnclaveAux::DepositStakeTx { tx, .. }) => {
                    inittx.put(COL_BODIES, &txid[..], &tx.encode());
                    // witness is obfuscated -- TODO: could be stored on the enclave side or thrown away?
                    // this is not necessary (as they are spent in deliver_tx) and more of a sanity check (as update_utxos_commit does it)
                    spend_utxos(&tx.inputs, self.storage.db.clone(), inittx);
                    // account should be already updated in deliver_tx
                }
                TxAux::UnbondStakeTx(tx, witness) => {
                    inittx.put(COL_BODIES, &txid[..], &tx.encode());
                    inittx.put(COL_WITNESS, &txid[..], &witness.encode());
                    // account should be already updated in deliver_tx
                }
                TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
                    witness,
                    no_of_outputs,
                    payload: TxObfuscated { txpayload, .. },
                    ..
                }) => {
                    // FIXME: temporary hack / this shouldn't be here
                    let plain_tx = PlainTxAux::decode(&mut txpayload.as_slice());
                    if let Ok(PlainTxAux::WithdrawUnbondedStakeTx(tx)) = plain_tx {
                        inittx.put(
                            COL_BODIES,
                            &txid[..],
                            &TxWithOutputs::StakeWithdraw(tx.clone()).encode(),
                        );
                    }

                    inittx.put(COL_WITNESS, &txid[..], &witness.encode());
                    // account should be already updated in deliver_tx
                    inittx.put(
                        COL_TX_META,
                        &txid[..],
                        &BitVec::from_elem(*no_of_outputs as usize, false).to_bytes(),
                    );
                }
                TxAux::UnjailTx(tx, witness) => {
                    inittx.put(COL_BODIES, &txid[..], &tx.encode());
                    inittx.put(COL_WITNESS, &txid[..], &witness.encode());
                    // account should be already unjailed in deliver_tx
                }
                TxAux::NodeJoinTx(tx, witness) => {
                    inittx.put(COL_BODIES, &txid[..], &tx.encode());
                    inittx.put(COL_WITNESS, &txid[..], &witness.encode());
                    // staked state updated in deliver_tx
                    // validator state updated in end_block
                }
            }
        }
    }
    /// Commits delivered TX: flushes updates to the underlying storage
    pub fn commit_handler(&mut self, _req: &RequestCommit) -> ResponseCommit {
        let orig_state = self.last_state.clone();
        let mut new_state = orig_state.expect("executing block commit, but no app state stored (i.e. no initchain or recovery was executed)");
        let mut top_level = &mut new_state.top_level;
        let mut resp = ResponseCommit::new();
        let mut inittx = self.storage.db.transaction();

        let ids: Vec<TxId> = self
            .delivered_txs
            .iter()
            .map(chain_core::tx::TxAux::tx_id)
            .collect();
        let tree = MerkleTree::new(ids);

        if !self.delivered_txs.is_empty() {
            self.process_txs(&mut inittx);
        }
        if self.rewards_pool_updated {
            top_level.rewards_pool.last_block_height = new_state.last_block_height;
            self.rewards_pool_updated = false;
        }
        top_level.account_root = self.uncommitted_account_root_hash;
        let app_hash = compute_app_hash(
            &tree,
            &top_level.account_root,
            &top_level.rewards_pool,
            &top_level.network_params,
        );
        inittx.put(COL_MERKLE_PROOFS, &app_hash[..], &tree.encode());
        new_state.last_apphash = app_hash;
        match self
            .tx_validator
            .process_request(EnclaveRequest::CommitBlock {
                app_hash,
                info: ChainInfo {
                    // TODO: fee computation in enclave?
                    min_fee_computed: top_level.network_params.calculate_fee(0).expect("base fee"),
                    chain_hex_id: self.chain_hex_id,
                    previous_block_time: new_state.block_time,
                    unbonding_period: top_level.network_params.get_unbonding_period(),
                },
            }) {
            EnclaveResponse::CommitBlock(Ok(_)) => {
                debug!("enclave storage persisted");
            }
            _ => {
                panic!("persisting enclave storage failed");
            }
        }

        inittx.put(COL_NODE_INFO, LAST_STATE_KEY, &new_state.encode());
        let encoded_height = i64::encode_var_vec(new_state.last_block_height);
        inittx.put(COL_APP_HASHS, &encoded_height, &new_state.last_apphash);
        if self.tx_query_address.is_some() {
            inittx.put(
                COL_APP_STATES,
                &encoded_height,
                &new_state.top_level.encode(),
            );
        }
        let wr = self.storage.db.write(inittx);
        if wr.is_err() {
            panic!("db write error: {}", wr.err().unwrap());
        } else {
            resp.data = new_state.last_apphash.to_vec();
            self.last_state = Some(new_state);
            self.delivered_txs.clear();
        }

        resp
    }
}
