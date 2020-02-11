use crate::{LookupItem, Storage, COL_BODIES, COL_MERKLE_PROOFS, COL_TX_META, COL_WITNESS};
use bit_vec::BitVec;
use chain_core::common::H256;
use chain_core::tx::data::input::{TxoIndex, TxoPointer};
use chain_core::tx::data::TxId;
use std::collections::BTreeMap;

pub enum InputStatus {
    Unspent,
    Spent,
}

pub enum InputError {
    InvalidTxId,
    InvalidIndex,
    IoError(std::io::Error),
}

impl Storage {
    /// Given a db and a DB transaction, it will go through TX inputs and mark them as spent
    /// in the TX_META storage.
    pub fn spend_utxos(&mut self, txins: &[TxoPointer]) {
        let mut updated_txs = BTreeMap::new();
        for txin in txins.iter() {
            updated_txs
                .entry(txin.id)
                .or_insert_with(|| {
                    BitVec::from_bytes(&self.db.get(COL_TX_META, &txin.id[..]).unwrap().unwrap())
                })
                .set(txin.index as usize, true);
        }
        let dbtx = self.get_or_create_tx();
        for (txid, bv) in &updated_txs {
            dbtx.put(COL_TX_META, &txid[..], &bv.to_bytes());
        }
    }

    pub fn create_utxo(&mut self, no_of_outputs: TxoIndex, txid: &TxId) {
        let dbtx = self.get_or_create_tx();
        dbtx.put(
            COL_TX_META,
            txid,
            &BitVec::from_elem(no_of_outputs as usize, false).to_bytes(),
        );
    }

    pub fn store_sealed_log(&mut self, txid: &TxId, sealed_log: &[u8]) {
        // FIXME
        self.temp_sealed_tx_store.insert(*txid, sealed_log.to_vec());
    }

    pub fn get_sealed_log(&self, txid: &TxId) -> Option<Vec<u8>> {
        // FIXME
        match self.temp_sealed_tx_store.get(txid) {
            None => self.lookup_item(LookupItem::TxSealed, txid),
            Some(x) => Some(x.clone()),
        }
    }

    pub fn store_tx_body(&mut self, txid: &TxId, tx_payload: &[u8]) {
        let dbtx = self.get_or_create_tx();
        dbtx.put(COL_BODIES, txid, tx_payload);
    }

    pub fn store_tx_witness(&mut self, txid: &TxId, witness_payload: &[u8]) {
        let dbtx = self.get_or_create_tx();
        dbtx.put(COL_WITNESS, txid, witness_payload);
    }

    pub fn store_txs_merkle_tree(&mut self, app_hash: &H256, tree_payload: &[u8]) {
        let dbtx = self.get_or_create_tx();
        dbtx.put(COL_MERKLE_PROOFS, app_hash, tree_payload);
    }

    /// returns the status of the given input (transaction output of a different tx)
    pub fn lookup_input(&self, txin: &TxoPointer) -> Result<InputStatus, InputError> {
        let txo = self.db.get(COL_TX_META, &txin.id[..]);
        match txo {
            Ok(Some(v)) => {
                let input_index = txin.index as usize;
                let bv = BitVec::from_bytes(&v).get(input_index);
                match bv {
                    None => Err(InputError::InvalidIndex),
                    Some(true) => Ok(InputStatus::Spent),
                    Some(false) => Ok(InputStatus::Unspent),
                }
            }
            Ok(None) => Err(InputError::InvalidTxId),
            Err(e) => Err(InputError::IoError(e)),
        }
    }

    pub fn write_buffered(&mut self) {
        let mtx = self.current_tx.take();
        if let Some(tx) = mtx {
            // this "buffered write" shouldn't persist (persistence done in commit)
            // but should change it in-memory
            // FIXME: https://github.com/crypto-com/chain/issues/885
            self.db.write_buffered(tx)
        }
    }
}
