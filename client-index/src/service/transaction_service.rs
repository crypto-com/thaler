use failure::ResultExt;
use rlp::{decode, encode};

use chain_core::tx::data::{Tx, TxId};
use client_common::{ErrorKind, Result, Storage};

const KEYSPACE: &str = "index_transaction";

/// Exposes functionalities for managing transactions
///
/// Stores `tx_id -> tx` mapping
pub struct TransactionService<S> {
    storage: S,
}

impl<S> TransactionService<S>
where
    S: Storage,
{
    /// Creates a new instance of transaction service
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Retrieves transaction with given id
    pub fn get(&self, id: &TxId) -> Result<Option<Tx>> {
        let bytes = self.storage.get(KEYSPACE, id)?;

        match bytes {
            None => Ok(None),
            Some(bytes) => Ok(Some(
                decode(&bytes).context(ErrorKind::DeserializationError)?,
            )),
        }
    }

    /// Sets transaction with given id and value
    pub fn set(&self, id: &TxId, transaction: &Tx) -> Result<()> {
        self.storage.set(KEYSPACE, id, encode(transaction))?;

        Ok(())
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}
