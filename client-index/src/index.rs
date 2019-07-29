//! Transaction index operations
mod default_index;
mod unauthorized_index;

pub use default_index::DefaultIndex;
pub use unauthorized_index::UnauthorizedIndex;

use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use client_common::{Result, Transaction};

use crate::AddressDetails;

/// Interface for interacting with transaction index
pub trait Index: Send + Sync {
    /// Returns details for given address
    fn address_details(&self, address: &ExtendedAddr) -> Result<AddressDetails>;

    /// Returns transaction with given id
    fn transaction(&self, id: &TxId) -> Result<Option<Transaction>>;

    /// Returns output of transaction with given id and index
    fn output(&self, input: &TxoPointer) -> Result<TxOut>;

    /// Broadcasts a transaction to Crypto.com Chain
    fn broadcast_transaction(&self, transaction: &[u8]) -> Result<()>;
}
