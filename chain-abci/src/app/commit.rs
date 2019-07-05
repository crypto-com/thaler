use super::ChainNodeApp;
use crate::app::spend_utxos;
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::*;
use abci::*;
use bit_vec::BitVec;
use chain_core::common::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::tx::data::Tx;
use chain_core::tx::data::TxId;
use chain_core::tx::TransactionId;
use chain_core::tx::TxAux;
use chain_tx_validation::TxWithOutputs;
use integer_encoding::VarInt;
use kvdb::{DBTransaction, KeyValueDB};
use parity_codec::Encode;
use std::sync::Arc;

/// Given a db and a DB transaction, it will go through TX inputs and mark them as spent
/// in the TX_META storage and it will create a new entry for TX in TX_META with all outputs marked as unspent.
pub fn update_utxos_commit(tx: &Tx, db: Arc<dyn KeyValueDB>, dbtx: &mut DBTransaction) {
    spend_utxos(&tx.inputs, db, dbtx);
    dbtx.put(
        COL_TX_META,
        &tx.id(),
        &BitVec::from_elem(tx.outputs.len(), false).to_bytes(),
    );
}

impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// Commits delivered TX: flushes updates to the underlying storage
    pub fn commit_handler(&mut self, _req: &RequestCommit) -> ResponseCommit {
        let orig_state = self.last_state.clone();
        let mut new_state = orig_state.expect("executing block commit, but no app state stored (i.e. no initchain or recovery was executed)");
        let mut resp = ResponseCommit::new();
        let mut inittx = self.storage.db.transaction();
        if !self.delivered_txs.is_empty() {
            let ids: Vec<TxId> = self
                .delivered_txs
                .iter()
                .map(chain_core::tx::TxAux::tx_id)
                .collect();
            let tree = MerkleTree::new(ids);
            for txaux in self.delivered_txs.iter() {
                let txid: TxId = txaux.tx_id();
                match &txaux {
                    TxAux::TransferTx(tx, witness) => {
                        inittx.put(
                            COL_BODIES,
                            &txid[..],
                            &TxWithOutputs::Transfer(tx.clone()).encode(),
                        );
                        inittx.put(COL_WITNESS, &txid[..], &witness.encode());
                        update_utxos_commit(&tx, self.storage.db.clone(), &mut inittx);
                    }
                    TxAux::DepositStakeTx(tx, witness) => {
                        inittx.put(COL_BODIES, &txid[..], &tx.encode());
                        inittx.put(COL_WITNESS, &txid[..], &witness.encode());
                        // this is not necessary (as they are spent in deliver_tx) and more of a sanity check (as update_utxos_commit does it)
                        spend_utxos(&tx.inputs, self.storage.db.clone(), &mut inittx);
                        // account should be already updated in deliver_tx
                    }
                    TxAux::UnbondStakeTx(tx, witness) => {
                        inittx.put(COL_BODIES, &txid[..], &tx.encode());
                        inittx.put(COL_WITNESS, &txid[..], &witness.encode());
                        // account should be already updated in deliver_tx
                    }
                    TxAux::WithdrawUnbondedStakeTx(tx, witness) => {
                        inittx.put(
                            COL_BODIES,
                            &txid[..],
                            &TxWithOutputs::StakeWithdraw(tx.clone()).encode(),
                        );
                        inittx.put(COL_WITNESS, &txid[..], &witness.encode());
                        // account should be already updated in deliver_tx
                        inittx.put(
                            COL_TX_META,
                            &txid[..],
                            &BitVec::from_elem(tx.outputs.len(), false).to_bytes(),
                        );
                    }
                }
            }
            new_state.rewards_pool.last_block_height = new_state.last_block_height;
            new_state.last_account_root_hash = self.uncommitted_account_root_hash;
            let app_hash = compute_app_hash(
                &tree,
                &new_state.last_account_root_hash,
                &new_state.rewards_pool,
            );
            inittx.put(COL_MERKLE_PROOFS, &app_hash[..], &tree.encode());
            new_state.last_apphash = app_hash;
        }

        inittx.put(
            COL_APP_STATES,
            &i64::encode_var_vec(new_state.last_block_height),
            &new_state.last_apphash,
        );
        inittx.put(COL_NODE_INFO, LAST_STATE_KEY, &new_state.encode());
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
