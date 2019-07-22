//! Observer for block-headers, transactions, etc.
mod default_transaction_handler;

pub use default_transaction_handler::DefaultTransactionHandler;

use chrono::{DateTime, Utc};

use client_common::{Result, Transaction};

/// Interface for handling stream of transactions in Crypto.com Chain
pub trait TransactionHandler: Send + Sync {
    /// Handles a transaction on Crypto.com Chain
    fn on_next(
        &self,
        transaction: Transaction,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<()>;
}
