use super::ChainNodeApp;
use crate::storage::tx::update_utxos_commit;
use crate::storage::*;
use abci::*;
use bincode::serialize;
use chain_core::common::merkle::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::tx::data::TxId;
use chain_core::tx::TxAux;
use integer_encoding::VarInt;
use rlp::Encodable;

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
                .map(|x| match x {
                    TxAux::TransferTx(tx, _) => tx.id(),
                })
                .collect();
            let tree = MerkleTree::new(&ids);
            for TxAux::TransferTx(tx, witness) in self.delivered_txs.iter() {
                let txid: TxId = tx.id();
                inittx.put(COL_BODIES, &txid.as_bytes(), &tx.rlp_bytes());
                inittx.put(COL_WITNESS, &txid.as_bytes(), &witness.rlp_bytes());
                update_utxos_commit(&tx, self.storage.db.clone(), &mut inittx);
            }
            new_state.rewards_pool.last_block_height = new_state.last_block_height;
            let app_hash = compute_app_hash(&tree, &new_state.rewards_pool);
            inittx.put(COL_MERKLE_PROOFS, &app_hash.as_bytes(), &tree.rlp_bytes());
            new_state.last_apphash = app_hash;
        }

        inittx.put(
            COL_APP_STATES,
            &i64::encode_var_vec(new_state.last_block_height.into()),
            &new_state.last_apphash.as_bytes(),
        );
        inittx.put(
            COL_NODE_INFO,
            LAST_STATE_KEY,
            &serialize(&new_state).expect("serialize state"),
        );
        let wr = self.storage.db.write(inittx);
        if wr.is_err() {
            panic!("db write error: {}", wr.err().unwrap());
        } else {
            resp.data = new_state.last_apphash.as_bytes().to_vec();
            self.last_state = Some(new_state);
        }

        resp
    }
}
