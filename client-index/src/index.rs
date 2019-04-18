//! Transaction index operations
mod default_index;

pub use default_index::DefaultIndex;

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::{Tx, TxId};
use client_common::balance::TransactionChange;
use client_common::Result;

/// Interface for interacting with transaction index
pub trait Index: Send + Sync {
    /// Synchronizes transaction index with Crypto.com Chain (from last known height)
    fn sync(&self) -> Result<()>;

    /// Synchronizes transaction index with Crypto.com Chain (from genesis)
    fn sync_all(&self) -> Result<()>;

    /// Returns all transaction changes for given address
    fn transaction_changes(&self, address: &ExtendedAddr) -> Result<Vec<TransactionChange>>;

    /// Returns current balance for given address
    fn balance(&self, address: &ExtendedAddr) -> Result<Coin>;

    /// Returns transaction with given id
    fn transaction(&self, id: &TxId) -> Result<Option<Tx>>;
}
