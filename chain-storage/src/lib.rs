mod api;
pub mod buffer;
pub mod jellyfish;

use crate::buffer::{flush_storage, BufferStore, Get, KVBuffer};
use crate::jellyfish::{put_stakings, Version};
use chain_core::common::H256;
use chain_core::state::account::StakedState;
use chain_core::state::tendermint::BlockHeight;
use chain_core::tx::data::TxId;
use kvdb::{DBTransaction, KeyValueDB};
use std::path::Path;
use std::sync::Arc;

pub use api::*;

// database columns
/// Column for UTXOs: TxId => BitVec (where each bit indicates whether the output was spent or not, e.g. b[0] == true if output 0 was spent in a given TX)
pub const COL_TX_META: u32 = 0;
/// Column for TX witnesses: TxId => TxWitness
pub const COL_WITNESS: u32 = 1;
/// Column for TX bodies: TxId => Tx
pub const COL_BODIES: u32 = 2;
/// Column for Extras: stores additional information, mainly retrieved during initialization (e.g. chain_id) -- TODO: better processing of these
pub const COL_EXTRA: u32 = 3;
/// Column for general information from the local node which can persist (e.g. last height, app hash...).
pub const COL_NODE_INFO: u32 = 4;
/// Column for seriliazed merkle tree: root hash => MerkleTree
pub const COL_MERKLE_PROOFS: u32 = 5;
/// Column for tracking app hashes: height => app hash
pub const COL_APP_HASHS: u32 = 6;
/// Column for tracking app states: height => ChainNodeState, only available when tx_query_address set
pub const COL_APP_STATES: u32 = 7;
/// Column for sealed transction payload: TxId => sealed tx payload (to MRSIGNER on a particular machine)
pub const COL_ENCLAVE_TX: u32 = 8;
/// Column for merkle trie storage
pub const COL_TRIE_NODE: u32 = 9;
/// Column for staled node key in merkle trie
pub const COL_TRIE_STALED: u32 = 10;
/// Number of columns in DB
pub const NUM_COLUMNS: u32 = 11;

pub const CHAIN_ID_KEY: &[u8] = b"chain_id";
pub const GENESIS_APP_HASH_KEY: &[u8] = b"genesis_app_hash";
pub const LAST_STATE_KEY: &[u8] = b"last_state";

pub enum StorageType {
    Node,
    AccountTrie,
}

/// Storage configuration -- currently only the path to RocksDB directory
/// TODO: other options? e.g. HDD vs SDD?
pub struct StorageConfig<'a> {
    base_dbs_path: &'a str,
    purpose: StorageType,
}

impl<'a> StorageConfig<'a> {
    pub fn new(base_dbs_path: &'a str, purpose: StorageType) -> Self {
        StorageConfig {
            base_dbs_path,
            purpose,
        }
    }

    pub fn db_path(&self) -> String {
        match self.purpose {
            StorageType::Node => Path::new(self.base_dbs_path)
                .join("chain")
                .to_str()
                .expect("invalid storage path")
                .to_string(),
            StorageType::AccountTrie => Path::new(self.base_dbs_path)
                .join("account")
                .to_str()
                .expect("invalid storage path")
                .to_string(),
        }
    }
}

/// Storage wrapper -- currently only holds the reference to KV DB.
/// It may hold caches or other look ups
pub struct Storage {
    db: Arc<dyn KeyValueDB>,
    /// tx to be committed
    current_tx: Option<DBTransaction>,
}

impl Get for Storage {
    type Key = (u32, Vec<u8>);
    type Value = Vec<u8>;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        let (col, key) = key;
        self.db.get(*col, &key).expect("kv storage io error")
    }
}

/// committed storage only
pub struct ReadOnlyStorage {
    db: Arc<dyn KeyValueDB>,
}

impl Get for ReadOnlyStorage {
    type Key = (u32, Vec<u8>);
    type Value = Vec<u8>;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        let (col, key) = key;
        self.db.get(*col, &key).expect("kv storage io error")
    }
}

impl ReadOnlyStorage {
    pub fn get_last_app_state(&self) -> Option<Vec<u8>> {
        self.db
            .get(COL_NODE_INFO, LAST_STATE_KEY)
            .expect("app state lookup")
            .map(|x| x.to_vec())
    }

    pub fn get_sealed_log(&self, txid: &TxId) -> Option<Vec<u8>> {
        self.db
            .get(COL_ENCLAVE_TX, txid)
            .expect("IO fail")
            .map(|x| x.to_vec())
    }
}

pub trait StoredChainState {
    /// get the whole state encoded
    fn get_encoded(&self) -> Vec<u8>;
    /// top level is the part of chain node state used in app hash computation
    fn get_encoded_top_level(&self) -> Vec<u8>;
    /// the last committed application hash
    fn get_last_app_hash(&self) -> H256;
}

#[repr(u32)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum LookupItem {
    TxBody = COL_BODIES,
    TxWitness = COL_WITNESS,
    TxMetaSpent = COL_TX_META,
    TxsMerkle = COL_MERKLE_PROOFS,
    TxSealed = COL_ENCLAVE_TX,
}

impl Storage {
    pub fn get_read_only(&self) -> ReadOnlyStorage {
        ReadOnlyStorage {
            db: self.db.clone(),
        }
    }

    pub fn lookup_item(&self, item_type: LookupItem, txid_or_app_hash: &H256) -> Option<Vec<u8>> {
        lookup_item(self, item_type, txid_or_app_hash)
    }

    /// initializes Storage with a provided reference to KV DB (used in testing / benches -- in-mem KVDB)
    #[allow(dead_code)]
    pub fn new_db(db: Arc<dyn KeyValueDB>) -> Self {
        Storage {
            db,
            current_tx: None,
        }
    }

    /// inititalizes Storage based on the provided config
    pub fn new(config: &StorageConfig<'_>) -> Self {
        let db = Arc::new(
            kvdb_rocksdb::Database::open(
                &kvdb_rocksdb::DatabaseConfig::with_columns(NUM_COLUMNS),
                &config.db_path(),
            )
            .expect("failed to open db"),
        );
        Storage {
            db,
            current_tx: None,
        }
    }

    fn get_or_create_tx(&mut self) -> &mut DBTransaction {
        match self.current_tx.as_mut() {
            Some(_tx) => {}
            None => {
                let tx = self.db.transaction();
                self.current_tx = Some(tx);
            }
        };
        self.current_tx.as_mut().unwrap()
    }

    pub fn get_sealed_log(&self, txid: &TxId) -> Option<Vec<u8>> {
        self.lookup_item(LookupItem::TxSealed, txid)
    }

    /// currently for potential debugging / diagnostics
    /// parameters are protobuf-serialized (what was passed in initchain)
    pub fn store_consensus_params(&mut self, cp: &[u8]) {
        let inittx = self.get_or_create_tx();
        inittx.put(COL_EXTRA, b"init_chain_consensus_params", cp);
    }

    pub fn get_genesis_app_hash(&self) -> H256 {
        get_genesis_app_hash(self).expect("last app state found, but genesis app hash not stored")
    }

    pub fn get_stored_chain_id(&self) -> Vec<u8> {
        get_stored_chain_id(self).expect("last app state found, but no chain id stored")
    }

    pub fn get_last_app_state(&self) -> Option<Vec<u8>> {
        get_last_app_state(self)
    }

    pub fn get_historical_state(&self, height: BlockHeight) -> Option<Vec<u8>> {
        get_historical_state(self, height)
    }

    pub fn get_historical_app_hash(&self, height: BlockHeight) -> Option<H256> {
        get_historical_app_hash(self, height)
    }

    pub fn write_genesis_chain_id(&mut self, genesis_app_hash: &H256, chain_id: &str) {
        let inittx = self.get_or_create_tx();
        inittx.put(COL_NODE_INFO, GENESIS_APP_HASH_KEY, genesis_app_hash);
        inittx.put(COL_EXTRA, CHAIN_ID_KEY, chain_id.as_bytes());
        let tx = self
            .current_tx
            .take()
            .expect("there should be a tx after `get_or_create_tx`");
        self.db
            .write(tx)
            .expect("genesis app hash should be stored");
    }

    pub fn persist_write(&mut self) -> std::io::Result<()> {
        if let Some(dbtx) = self.current_tx.take() {
            self.db.write(dbtx)
        } else {
            Ok(())
        }
    }

    pub fn put_stakings(&mut self, version: Version, stakings: &[StakedState]) -> H256 {
        let mut kv_buffer = KVBuffer::new();
        let root_hash = put_stakings(
            &mut BufferStore::new(self, &mut kv_buffer),
            version,
            stakings.iter(),
        )
        .unwrap();
        flush_storage(self, kv_buffer).unwrap();
        root_hash
    }
}
