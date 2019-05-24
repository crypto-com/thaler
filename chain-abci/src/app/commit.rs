use super::ChainNodeApp;
use crate::storage::tx::update_utxos_commit;
use crate::storage::*;
use abci::*;
use chain_core::common::merkle::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::tx::data::TxId;
use chain_core::tx::TxAux;
use integer_encoding::VarInt;
use parity_codec::Encode;

impl ChainNodeApp {
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
            let tree = MerkleTree::new(&ids);
            for txaux in self.delivered_txs.iter() {
                match txaux {
                    TxAux::TransferTx(tx, witness) => {
                        let txid: TxId = tx.id();
                        inittx.put(COL_BODIES, &txid[..], &tx.encode());
                        inittx.put(COL_WITNESS, &txid[..], &witness.encode());
                        update_utxos_commit(&tx, self.storage.db.clone(), &mut inittx);
                    }
                    _ => unimplemented!("MUST_TODO -- account-related TX commits"),
                }
            }
            new_state.rewards_pool.last_block_height = new_state.last_block_height;
            let app_hash = compute_app_hash(&tree, &new_state.rewards_pool);
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
