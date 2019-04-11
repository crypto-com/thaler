use rlp::{decode_list, encode, encode_list};

use chain_core::tx::data::address::ExtendedAddr;
use client_common::balance::TransactionChange;
use client_common::{Result, Storage};

const KEYSPACE: &str = "index_address";

/// Exposes functionalities for managing addresses
///
/// Stores `address -> [tx_changes]` mapping
pub struct AddressService<S> {
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
        let bytes = self.storage.get(KEYSPACE, encode(address))?;

        match bytes {
            None => Ok(Default::default()),
            Some(bytes) => Ok(decode_list(&bytes)),
        }
    }

    /// Adds a new transaction change for given address
    pub fn add(&self, change: TransactionChange) -> Result<()> {
        let address = change.address.clone();

        let mut changes = self.get(&address)?;
        changes.push(change);

        self.storage
            .set(KEYSPACE, encode(&address), encode_list(&changes))?;

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

    use chain_core::init::coin::Coin;
    use chain_core::tx::data::txid_hash;
    use client_common::balance::BalanceChange;
    use client_common::storage::MemoryStorage;

    #[test]
    fn check_flow() {
        let address_service = AddressService::new(MemoryStorage::default());
        let address = ExtendedAddr::BasicRedeem(Default::default());
        let transaction_change = TransactionChange {
            transaction_id: txid_hash(&[0, 1, 2]),
            address: address.clone(),
            balance_change: BalanceChange::Incoming(
                Coin::new(30).expect("Unable to create new coin"),
            ),
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
