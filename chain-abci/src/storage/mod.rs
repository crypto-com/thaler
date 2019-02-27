pub mod merkle;
pub mod tx;

use kvdb::KeyValueDB;
use std::sync::Arc;

// database columns
/// Column for UTXOs: TxId => BitVec (where each bit indicates whether the output was spent or not, e.g. b[0] == true if output 0 was spent in a given TX)
pub const COL_TX_META: Option<u32> = Some(0);
/// Column for TX witnesses: TxId => TxWitness
pub const COL_WITNESS: Option<u32> = Some(1);
/// Column for TX bodies: TxId => Tx
pub const COL_BODIES: Option<u32> = Some(2);
/// Column for Extras: stores additional information, mainly retrieved during initialization (e.g. chain_id) -- TODO: better processing of these
pub const COL_EXTRA: Option<u32> = Some(3);
/// Column for general information from the local node which can persist (e.g. last height, app hash...).
pub const COL_NODE_INFO: Option<u32> = Some(4);
/// Column for seriliazed merkle tree: root hash => MerkleTree
pub const COL_MERKLE_PROOFS: Option<u32> = Some(5);
/// Column for tracking app states: height => root hash
pub const COL_APP_STATES: Option<u32> = Some(6);
/// Number of columns in DB
pub const NUM_COLUMNS: Option<u32> = Some(7);

pub const CHAIN_ID_KEY: &[u8] = b"chain_id";
pub const GENESIS_APP_HASH_KEY: &[u8] = b"genesis_app_hash";
pub const LAST_APP_HASH_KEY: &[u8] = b"last_app_hash";
pub const LAST_BLOCK_HEIGHT_KEY: &[u8] = b"last_block_height";
pub const BLOCK_TIME_KEY: &[u8] = b"block_time";

/// Storage configuration -- currently only the path to RocksDB directory
/// TODO: other options? e.g. HDD vs SDD?
pub struct StorageConfig<'a> {
    pub db_path: &'a str,
}

/// Storage wrapper -- currently only holds the reference to KV DB.
/// It may hold caches or other look ups (TODO: reconsider whether necessary and if db could be moved up to App)
pub struct Storage {
    pub db: Arc<KeyValueDB>,
}

impl Storage {
    /// initializes Storage with a provided reference to KV DB (used in testing / benches -- in-mem KVDB)
    #[allow(dead_code)]
    pub fn new_db(db: Arc<KeyValueDB>) -> Self {
        Storage { db }
    }

    /// inititalizes Storage based on the provided config
    pub fn new(config: &StorageConfig) -> Self {
        let db = Arc::new(
            kvdb_rocksdb::Database::open(
                &kvdb_rocksdb::DatabaseConfig::with_columns(NUM_COLUMNS),
                config.db_path,
            )
            .expect("failed to open db"),
        );
        Storage { db }
    }
}
