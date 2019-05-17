use chain_core::tx::data::{Tx, TxId};
use client_common::{Result, Storage};
use parity_codec::{Decode, Encode};

const KEYSPACE: &str = "index_transaction";

/// Exposes functionalities for managing transactions
///
/// Stores `tx_id -> tx` mapping
#[derive(Default, Clone)]
pub struct TransactionService<S: Storage> {
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
            Some(bytes) => Ok(Tx::decode(&mut bytes.as_slice())),
        }
    }

    /// Sets transaction with given id and value
    pub fn set(&self, id: &TxId, transaction: &Tx) -> Result<()> {
        self.storage.set(KEYSPACE, id, transaction.encode())?;

        Ok(())
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use client_common::storage::MemoryStorage;

    #[test]
    fn check_flow() {
        let transaction_service = TransactionService::new(MemoryStorage::default());
        let id = [0u8; 32];
        let transaction = Tx::default();

        assert_eq!(None, transaction_service.get(&id).unwrap());
        assert!(transaction_service.set(&id, &transaction).is_ok());
        assert_eq!(transaction, transaction_service.get(&id).unwrap().unwrap());
        assert!(transaction_service.clear().is_ok());
        assert_eq!(None, transaction_service.get(&id).unwrap());
    }
}
