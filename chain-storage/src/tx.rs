use crate::{LookupItem, Storage};
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
    /// (expects existing tx)
    pub fn spend_utxos(&mut self, txins: &[TxoPointer]) {
        let mut updated_txs = BTreeMap::new();
        let col = LookupItem::TxMetaSpent;
        for txin in txins.iter() {
            updated_txs
                .entry(txin.id)
                .or_insert_with(|| {
                    BitVec::from_bytes(
                        &self
                            .lookup_item(col, &txin.id, true)
                            .expect("tx meta create for existing utxo"),
                    )
                })
                .set(txin.index as usize, true);
        }
        for (txid, bv) in &updated_txs {
            self.insert_item(col, *txid, bv.to_bytes());
        }
    }

    pub fn create_utxo(&mut self, no_of_outputs: TxoIndex, txid: &TxId) {
        self.insert_item(
            LookupItem::TxMetaSpent,
            *txid,
            BitVec::from_elem(no_of_outputs as usize, false).to_bytes(),
        );
    }

    pub fn store_sealed_log(&mut self, txid: &TxId, sealed_log: &[u8]) {
        self.insert_item(LookupItem::TxSealed, *txid, sealed_log.to_vec());
    }

    pub fn get_sealed_log(&self, txid: &TxId) -> Option<Vec<u8>> {
        self.lookup_item(LookupItem::TxSealed, txid, true)
    }

    pub fn store_tx_body(&mut self, txid: &TxId, tx_payload: &[u8]) {
        self.insert_item(LookupItem::TxBody, *txid, tx_payload.to_vec());
    }

    pub fn store_tx_witness(&mut self, txid: &TxId, witness_payload: &[u8]) {
        self.insert_item(LookupItem::TxWitness, *txid, witness_payload.to_vec());
    }

    pub fn store_txs_merkle_tree(&mut self, app_hash: &H256, tree_payload: &[u8]) {
        self.insert_item(LookupItem::TxsMerkle, *app_hash, tree_payload.to_vec());
    }

    /// returns the status of the given input (transaction output of a different tx)
    pub fn lookup_input(
        &self,
        txin: &TxoPointer,
        read_uncommitted: bool,
    ) -> Result<InputStatus, InputError> {
        let txo = self.lookup_item(LookupItem::TxMetaSpent, &txin.id, read_uncommitted);
        match txo {
            Some(v) => {
                let input_index = txin.index as usize;
                let bv = BitVec::from_bytes(&v).get(input_index);
                match bv {
                    None => Err(InputError::InvalidIndex),
                    Some(true) => Ok(InputStatus::Spent),
                    Some(false) => Ok(InputStatus::Unspent),
                }
            }
            None => Err(InputError::InvalidTxId),
        }
    }
}
