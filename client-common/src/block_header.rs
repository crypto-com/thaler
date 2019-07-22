use chrono::{DateTime, Utc};

use chain_core::tx::data::TxId;
use chain_tx_filter::BlockFilter;

/// Structure for representing a block header on Crypto.com Chain
pub struct BlockHeader {
    /// Block height
    pub block_height: u64,
    /// Block time
    pub block_time: DateTime<Utc>,
    /// List of successfully committed transaction ids in this block
    pub transaction_ids: Vec<TxId>,
    /// Bloom filter for view keys
    pub view_key_filter: BlockFilter,
}
