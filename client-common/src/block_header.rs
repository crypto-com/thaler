use chrono::{DateTime, Utc};

use chain_core::tx::data::TxId;
use chain_tx_filter::BlockFilter;

use crate::Transaction;

/// Structure for representing a block header on Crypto.com Chain
#[derive(Debug)]
pub struct BlockHeader {
    /// App hash of block
    pub app_hash: String,
    /// Block height
    pub block_height: u64,
    /// Block time
    pub block_time: DateTime<Utc>,
    /// List of successfully committed transaction ids in this block
    pub transaction_ids: Vec<TxId>,
    /// Bloom filter for view keys and staking addresses
    pub block_filter: BlockFilter,
    /// List of un-encrypted transactions (only contains transactions of type `DepositStake` and `UnbondStake`)
    pub unencrypted_transactions: Vec<Transaction>,
}
