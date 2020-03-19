use std::collections::BTreeMap;

use bit_vec::BitVec;
use parity_scale_codec::Encode;

use chain_core::common::H256;
use chain_core::state::tendermint::BlockHeight;
use chain_core::tx::data::{
    input::{TxoIndex, TxoPointer},
    TxId,
};

use super::buffer::{GetKV, StoreKV};
use super::{
    LookupItem, StoredChainState, CHAIN_ID_KEY, COL_APP_HASHS, COL_APP_STATES, COL_EXTRA,
    COL_NODE_INFO, GENESIS_APP_HASH_KEY, LAST_STATE_KEY,
};

pub fn get_last_app_state(db: &impl GetKV) -> Option<Vec<u8>> {
    db.get(&(COL_NODE_INFO, LAST_STATE_KEY.to_vec()))
}

pub fn get_sealed_log(db: &impl GetKV, txid: &TxId) -> Option<Vec<u8>> {
    lookup_item(db, LookupItem::TxSealed, txid)
}

pub fn lookup_item(
    db: &impl GetKV,
    item_type: LookupItem,
    txid_or_app_hash: &H256,
) -> Option<Vec<u8>> {
    let col = item_type as u32;
    db.get(&(col, txid_or_app_hash.to_vec()))
}

pub fn insert_item(
    db: &mut impl StoreKV,
    item_type: LookupItem,
    txid_or_app_hash: H256,
    data: Vec<u8>,
) {
    let col = item_type as u32;
    db.set((col, txid_or_app_hash.to_vec()), data)
}

pub fn get_genesis_app_hash(db: &impl GetKV) -> Option<H256> {
    let value = db.get(&(COL_NODE_INFO, GENESIS_APP_HASH_KEY.to_vec()))?;
    let mut app_hash = H256::default();
    app_hash.copy_from_slice(&value);
    Some(app_hash)
}

pub fn get_stored_chain_id(db: &impl GetKV) -> Option<Vec<u8>> {
    db.get(&(COL_EXTRA, CHAIN_ID_KEY.to_vec()))
}

pub fn get_historical_state(db: &impl GetKV, height: BlockHeight) -> Option<Vec<u8>> {
    db.get(&(COL_APP_STATES, height.encode()))
}

pub fn get_historical_app_hash(db: &impl GetKV, height: BlockHeight) -> Option<H256> {
    let sah = db.get(&(COL_APP_HASHS, height.encode()))?;
    let mut stored_ah = H256::default();
    stored_ah.copy_from_slice(&sah);
    Some(stored_ah)
}

pub fn store_chain_state<T: StoredChainState>(
    db: &mut impl StoreKV,
    genesis_state: &T,
    block_height: BlockHeight,
    write_history_states: bool,
) {
    db.set(
        (COL_NODE_INFO, LAST_STATE_KEY.to_vec()),
        genesis_state.get_encoded(),
    );
    let encoded_height = block_height.encode();
    db.set(
        (COL_APP_HASHS, encoded_height.clone()),
        genesis_state.get_last_app_hash().to_vec(),
    );
    if write_history_states {
        db.set(
            (COL_APP_STATES, encoded_height),
            genesis_state.get_encoded_top_level(),
        );
    }
}

pub fn store_genesis_state<T: StoredChainState>(
    db: &mut impl StoreKV,
    genesis_state: &T,
    write_history_states: bool,
) {
    store_chain_state(
        db,
        genesis_state,
        BlockHeight::genesis(),
        write_history_states,
    );
}

pub fn write_genesis_chain_id(db: &mut impl StoreKV, genesis_app_hash: &H256, chain_id: &str) {
    db.set(
        (COL_NODE_INFO, GENESIS_APP_HASH_KEY.to_vec()),
        genesis_app_hash.to_vec(),
    );
    db.set(
        (COL_EXTRA, CHAIN_ID_KEY.to_vec()),
        chain_id.as_bytes().to_vec(),
    );
}

pub fn spend_utxos(db: &mut impl StoreKV, txins: &[TxoPointer]) {
    let mut updated_txs = BTreeMap::new();
    let col = LookupItem::TxMetaSpent;
    for txin in txins.iter() {
        updated_txs
            .entry(txin.id)
            .or_insert_with(|| {
                BitVec::from_bytes(
                    &lookup_item(db, col, &txin.id).expect("tx meta create for existing utxo"),
                )
            })
            .set(txin.index as usize, true);
    }
    for (txid, bv) in &updated_txs {
        insert_item(db, col, *txid, bv.to_bytes());
    }
}

pub fn create_utxo(db: &mut impl StoreKV, no_of_outputs: TxoIndex, txid: &TxId) {
    insert_item(
        db,
        LookupItem::TxMetaSpent,
        *txid,
        BitVec::from_elem(no_of_outputs as usize, false).to_bytes(),
    );
}

pub fn store_sealed_log(db: &mut impl StoreKV, txid: &TxId, sealed_log: &[u8]) {
    insert_item(db, LookupItem::TxSealed, *txid, sealed_log.to_vec());
}

pub fn store_tx_body(db: &mut impl StoreKV, txid: &TxId, tx_payload: &[u8]) {
    insert_item(db, LookupItem::TxBody, *txid, tx_payload.to_vec());
}

pub fn store_tx_witness(db: &mut impl StoreKV, txid: &TxId, witness_payload: &[u8]) {
    insert_item(db, LookupItem::TxWitness, *txid, witness_payload.to_vec());
}

pub fn store_txs_merkle_tree(db: &mut impl StoreKV, app_hash: &H256, tree_payload: &[u8]) {
    insert_item(db, LookupItem::TxsMerkle, *app_hash, tree_payload.to_vec());
}

pub fn lookup_input(db: &impl GetKV, txin: &TxoPointer) -> Option<bool> {
    lookup_item(db, LookupItem::TxMetaSpent, &txin.id)
        .and_then(|v| BitVec::from_bytes(&v).get(txin.index as usize))
}
