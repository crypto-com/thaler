use super::ChainNodeApp;
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::tx::update_utxos_commit;
use crate::storage::*;
use abci::*;
use chain_core::common::merkle::MerkleTree;
use chain_core::tx::data::TxId;
use integer_encoding::VarInt;
use serde_cbor::ser::to_vec_packed;

impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// Commits delivered TX: flushes updates to the underlying storage
    pub fn commit_handler(&mut self, _req: &RequestCommit) -> ResponseCommit {
        let mut resp = ResponseCommit::new();
        let mut inittx = self.storage.db.transaction();
        let app_hash = if !self.delivered_txs.is_empty() {
            let ids: Vec<TxId> = self.delivered_txs.iter().map(|x| x.tx.id()).collect();
            let tree = MerkleTree::new(&ids);
            for txaux in self.delivered_txs.iter() {
                let tx = &txaux.tx;
                let txid = tx.id();
                inittx.put(COL_BODIES, &txid, &to_vec_packed(&tx).unwrap());
                inittx.put(COL_WITNESS, &txid, &to_vec_packed(&txaux.witness).unwrap());
                update_utxos_commit(&txaux, self.storage.db.clone(), &mut inittx);
            }
            let app_hash = tree.get_root_hash();
            inittx.put(COL_NODE_INFO, LAST_APP_HASH_KEY, &app_hash);
            inittx.put(
                COL_NODE_INFO,
                LAST_BLOCK_HEIGHT_KEY,
                &i64::encode_var_vec(self.uncommitted_block_height),
            );
            inittx.put(COL_MERKLE_PROOFS, &app_hash, &to_vec_packed(&tree).unwrap());
            Some(app_hash)
        } else {
            self.last_apphash
        };

        if app_hash.is_some() {
            inittx.put(
                COL_APP_STATES,
                &i64::encode_var_vec(self.uncommitted_block_height),
                &app_hash.unwrap(),
            );
            let wr = self.storage.db.write(inittx);
            if wr.is_err() {
                // TODO: panic?
                println!("db write error: {}", wr.err().unwrap());
            } else {
                self.last_block_height = self.uncommitted_block_height;
                self.last_apphash = app_hash;
                self.uncommitted_block = false;
                resp.data = app_hash.unwrap().to_vec();
            }
        }

        resp
    }
}
