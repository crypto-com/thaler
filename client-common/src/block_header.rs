use chain_core::tx::data::TxId;
use chain_tx_filter::BlockFilter;

use crate::tendermint::types::Time;
use crate::Transaction;

/// Structure for representing a block header on Crypto.com Chain
#[derive(Debug)]
pub struct BlockHeader {
    /// App hash of block
    pub app_hash: String,
    /// Block height
    pub block_height: u64,
    /// Block time
    pub block_time: Time,
    /// List of successfully committed transaction ids in this block
    pub valid_transaction_ids: Vec<TxId>,
    /// Bloom filter for view keys and staking addresses
    pub block_filter: BlockFilter,
    /// List of successfully committed transaction of transactions that may need to be queried against
    pub enclave_transaction_ids: Vec<TxId>,
    /// List of un-encrypted transactions (only contains transactions of type `DepositStake` and `UnbondStake`)
    pub staking_transactions: Vec<Transaction>,
}
