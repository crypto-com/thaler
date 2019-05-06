use super::ChainNodeApp;
use crate::storage::tx::update_utxos_commit;
use crate::storage::*;
use abci::*;
use chain_core::common::merkle::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::tx::data::TxId;
use chain_core::tx::TxAux;
use integer_encoding::VarInt;
use rlp::Encodable;

impl ChainNodeApp {
    /// Commits delivered TX: flushes updates to the underlying storage
    pub fn commit_handler(&mut self, _req: &RequestCommit) -> ResponseCommit {
        let mut resp = ResponseCommit::new();
        let mut inittx = self.storage.db.transaction();
        let app_hash = if !self.delivered_txs.is_empty() {
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
            let rp = self.rewards_pool.clone().unwrap();
            let app_hash = compute_app_hash(&tree, &rp);
            inittx.put(COL_NODE_INFO, REWARDS_POOL_STATE_KEY, &rp.rlp_bytes());
            inittx.put(COL_NODE_INFO, LAST_APP_HASH_KEY, &app_hash.as_bytes());
            inittx.put(
                COL_NODE_INFO,
                LAST_BLOCK_HEIGHT_KEY,
                &i64::encode_var_vec(self.uncommitted_block_height.into()),
            );
            inittx.put(COL_MERKLE_PROOFS, &app_hash.as_bytes(), &tree.rlp_bytes());
            Some(app_hash)
        } else {
            self.last_apphash
        };

        if app_hash.is_some() {
            inittx.put(
                COL_APP_STATES,
                &i64::encode_var_vec(self.uncommitted_block_height.into()),
                &app_hash.unwrap().as_bytes(),
            );
            let wr = self.storage.db.write(inittx);
            if wr.is_err() {
                panic!("db write error: {}", wr.err().unwrap());
            } else {
                self.last_block_height = self.uncommitted_block_height;
                self.last_apphash = app_hash;
                resp.data = app_hash.unwrap().as_bytes().to_vec();
            }
        }

        resp
    }
}
