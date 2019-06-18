use chain_core::tx::data::address::ExtendedAddr;
use client_common::balance::TransactionChange;
use client_common::{ErrorKind, Result, Storage};
use parity_codec::{Decode, Encode};

const KEYSPACE: &str = "index_address";

/// Exposes functionalities for managing addresses
///
/// Stores `address -> [tx_changes]` mapping
#[derive(Default, Clone)]
pub struct TransactionChangeService<S: Storage> {
    storage: S,
}

impl<S> TransactionChangeService<S>
where
    S: Storage,
{
    /// Creates a new instance of address service
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Retrieves transaction changes for given address
    pub fn get(&self, address: &ExtendedAddr) -> Result<Vec<TransactionChange>> {
        self.storage
            .get(KEYSPACE, address.encode())?
            .map(|bytes| {
                Ok(Vec::decode(&mut bytes.as_slice()).ok_or(ErrorKind::DeserializationError)?)
            })
            .unwrap_or_else(|| Ok(Default::default()))
    }

    /// Adds a new transaction change for given address
    pub fn add(&self, change: &TransactionChange) -> Result<()> {
        self.storage
            .fetch_and_update(KEYSPACE, change.address.encode(), |value| {
                let mut changes = value
                    .map(|mut bytes| -> Result<Vec<TransactionChange>> {
                        Ok(Vec::decode(&mut bytes).ok_or(ErrorKind::DeserializationError)?)
                    })
                    .unwrap_or_else(|| Ok(Default::default()))?;
                changes.push(change.clone());

                Ok(Some(changes.encode()))
            })
            .map(|_| ())
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::SystemTime;

    use chrono::DateTime;

    use chain_core::init::coin::Coin;
    use chain_core::tx::data::txid_hash;
    use client_common::balance::BalanceChange;
    use client_common::storage::MemoryStorage;

    #[test]
    fn check_flow() {
        let transaction_change_service = TransactionChangeService::new(MemoryStorage::default());
        let address = ExtendedAddr::BasicRedeem(Default::default());
        let transaction_change = TransactionChange {
            transaction_id: txid_hash(&[0, 1, 2]),
            address: address.clone(),
            balance_change: BalanceChange::Incoming(
                Coin::new(30).expect("Unable to create new coin"),
            ),
            height: 1,
            time: DateTime::from(SystemTime::now()),
        };

        assert_eq!(0, transaction_change_service.get(&address).unwrap().len());
        assert!(transaction_change_service.add(&transaction_change).is_ok());
        assert_eq!(1, transaction_change_service.get(&address).unwrap().len());
        assert!(transaction_change_service.add(&transaction_change).is_ok());
        assert_eq!(2, transaction_change_service.get(&address).unwrap().len());
        assert!(transaction_change_service.clear().is_ok());
        assert_eq!(0, transaction_change_service.get(&address).unwrap().len());
    }
}
