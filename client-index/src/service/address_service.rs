use chain_core::tx::data::address::ExtendedAddr;
use client_common::balance::TransactionChange;
use client_common::{ErrorKind, Result, Storage};
use parity_codec::{Decode, Encode};

const KEYSPACE: &str = "index_address";

/// Exposes functionalities for managing addresses
///
/// Stores `address -> [tx_changes]` mapping
#[derive(Default, Clone)]
pub struct AddressService<S: Storage> {
    storage: S,
}

impl<S> AddressService<S>
where
    S: Storage,
{
    /// Creates a new instance of address service
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Retrieves transaction changes for given address
    pub fn get(&self, address: &ExtendedAddr) -> Result<Vec<TransactionChange>> {
        let bytes = self.storage.get(KEYSPACE, address.encode())?;

        match bytes {
            None => Ok(Default::default()),
            Some(bytes) => {
                Ok(Vec::decode(&mut bytes.as_slice()).ok_or(ErrorKind::DeserializationError)?)
            }
        }
    }

    /// Adds a new transaction change for given address
    pub fn add(&self, change: TransactionChange) -> Result<()> {
        let address = change.address.clone();

        let mut changes = self.get(&address)?;
        changes.push(change);

        self.storage
            .set(KEYSPACE, &address.encode(), changes.encode())?;

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

    use std::time::SystemTime;

    use chrono::DateTime;

    use chain_core::init::coin::Coin;
    use chain_core::tx::data::txid_hash;
    use client_common::balance::BalanceChange;
    use client_common::serializable::SerializableCoin;
    use client_common::storage::MemoryStorage;

    #[test]
    fn check_flow() {
        let address_service = AddressService::new(MemoryStorage::default());
        let address = ExtendedAddr::BasicRedeem(Default::default());
        let transaction_change = TransactionChange {
            transaction_id: txid_hash(&[0, 1, 2]),
            address: address.clone(),
            balance_change: BalanceChange::Incoming(SerializableCoin(
                Coin::new(30).expect("Unable to create new coin"),
            )),
            height: 1,
            time: DateTime::from(SystemTime::now()),
        };

        assert_eq!(0, address_service.get(&address).unwrap().len());
        assert!(address_service.add(transaction_change.clone()).is_ok());
        assert_eq!(1, address_service.get(&address).unwrap().len());
        assert!(address_service.add(transaction_change).is_ok());
        assert_eq!(2, address_service.get(&address).unwrap().len());
        assert!(address_service.clear().is_ok());
        assert_eq!(0, address_service.get(&address).unwrap().len());
    }
}
