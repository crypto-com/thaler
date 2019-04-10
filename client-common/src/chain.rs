//! Communication between client and chain
use crate::balance::TransactionChange;
use crate::Result;

/// Interface for a backend agnostic communication between client and chain
///
/// ### Warning
/// This is a WIP trait and will change in future based on requirements.
pub trait Chain {
    /// Queries Crypto.com chain for changes for different `addresses` from `last_block_height`
    fn query_transaction_changes(
        &self,
        addresses: Vec<String>,
        last_block_height: u64,
    ) -> Result<(Vec<TransactionChange>, u64)>;
}
