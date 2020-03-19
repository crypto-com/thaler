use std::mem;

use super::ChainNodeApp;
use crate::enclave_bridge::EnclaveProxy;
use abci::*;
use chain_core::common::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::tx::data::input::{TxoIndex, TxoPointer};
use chain_core::tx::data::TxId;
use chain_core::tx::{TxAux, TxEnclaveAux, TxPublicAux};
use chain_storage::buffer::{flush_staking_storage, flush_storage, StoreKV};
use parity_scale_codec::Encode;

/// Given a db and a DB transaction, it will go through TX inputs and mark them as spent
/// in the TX_META storage and it will create a new entry for TX in TX_META with all outputs marked as unspent.
fn update_utxos_commit(
    inputs: &[TxoPointer],
    no_of_outputs: TxoIndex,
    txid: TxId,
    db: &mut impl StoreKV,
) {
    chain_storage::spend_utxos(db, &inputs);
    chain_storage::create_utxo(db, no_of_outputs, &txid);
}

fn process_txs(delivered_txs: &[TxAux], db: &mut impl StoreKV) {
    for txaux in delivered_txs.iter() {
        let txid: TxId = txaux.tx_id();
        match &txaux {
            TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
                inputs,
                no_of_outputs,
                ..
            }) => {
                update_utxos_commit(&inputs, *no_of_outputs, txid, db);
            }
            TxAux::EnclaveTx(TxEnclaveAux::DepositStakeTx { tx, .. }) => {
                chain_storage::store_tx_body(db, &txid, &tx.encode());
                // witness is obfuscated -- TODO: could be stored on the enclave side or thrown away?
                // this is not necessary (as they are spent in deliver_tx) and more of a sanity check (as update_utxos_commit does it)
                chain_storage::spend_utxos(db, &tx.inputs);
                // account should be already updated in deliver_tx
            }
            TxAux::PublicTx(TxPublicAux::UnbondStakeTx(tx, witness)) => {
                chain_storage::store_tx_body(db, &txid, &tx.encode());
                chain_storage::store_tx_witness(db, &txid, &witness.encode());
                // account should be already updated in deliver_tx
            }
            TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
                witness,
                no_of_outputs,
                ..
            }) => {
                chain_storage::store_tx_witness(db, &txid, &witness.encode());
                // account should be already updated in deliver_tx
                chain_storage::create_utxo(db, *no_of_outputs, &txid);
            }
            TxAux::PublicTx(TxPublicAux::UnjailTx(tx, witness)) => {
                chain_storage::store_tx_body(db, &txid, &tx.encode());
                chain_storage::store_tx_witness(db, &txid, &witness.encode());
                // account should be already unjailed in deliver_tx
            }
            TxAux::PublicTx(TxPublicAux::NodeJoinTx(tx, witness)) => {
                chain_storage::store_tx_body(db, &txid, &tx.encode());
                chain_storage::store_tx_witness(db, &txid, &witness.encode());
                // staked state updated in deliver_tx
                // validator state updated in end_block
            }
        }
    }
}

impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// Commits delivered TX: flushes updates to the underlying storage
    pub fn commit_handler(&mut self, _req: &RequestCommit) -> ResponseCommit {
        let new_state = self.last_state.as_mut().expect("executing block commit, but no app state stored (i.e. no initchain or recovery was executed)");
        let mut top_level = &mut new_state.top_level;
        let mut resp = ResponseCommit::new();

        let ids: Vec<TxId> = self
            .delivered_txs
            .iter()
            .map(chain_core::tx::TxAux::tx_id)
            .collect();
        let tree = MerkleTree::new(ids);

        if !self.delivered_txs.is_empty() {
            process_txs(&self.delivered_txs, &mut kv_store!(self));
        }
        if self.rewards_pool_updated {
            top_level.rewards_pool.last_block_height = new_state.last_block_height;
            self.rewards_pool_updated = false;
        }
        // flush staking storage
        top_level.account_root = flush_staking_storage(
            &mut self.accounts,
            Some(top_level.account_root),
            mem::take(&mut self.staking_buffer),
        )
        .expect("merkle trie io error")
        .expect("merkle trie update should return Some(root)");

        let app_hash = compute_app_hash(
            &tree,
            &top_level.account_root,
            &top_level.rewards_pool,
            &top_level.network_params,
        );
        new_state.last_apphash = app_hash;

        chain_storage::store_txs_merkle_tree(&mut kv_store!(self), &app_hash, &tree.encode());
        chain_storage::store_chain_state(
            &mut kv_store!(self),
            &*new_state,
            new_state.last_block_height,
            self.tx_query_address.is_some(),
        );

        // flush key-value storage
        flush_storage(&mut self.storage, mem::take(&mut self.kv_buffer))
            .expect("kv storage io error");

        resp.data = new_state.last_apphash.to_vec();

        self.mempool_state = Some(new_state.clone());
        self.delivered_txs.clear();
        self.mempool_kv_buffer.clear();
        self.mempool_staking_buffer.clear();
        resp
    }
}
