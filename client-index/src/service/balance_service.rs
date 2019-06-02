use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::balance::BalanceChange;
use client_common::serializable::SerializableCoin;
use client_common::{ErrorKind, Result, Storage};
use parity_codec::{Decode, Encode};

const KEYSPACE: &str = "index_balance";

/// Exposes functionalities for managing balances
///
/// Stores `address -> balance` mapping
#[derive(Default, Clone)]
pub struct BalanceService<S: Storage> {
    storage: S,
}

impl<S> BalanceService<S>
where
    S: Storage,
{
    /// Creates a new instance of balance service
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Retrieves current balance for given address
    pub fn get(&self, address: &ExtendedAddr) -> Result<SerializableCoin> {
        let bytes = self.storage.get(KEYSPACE, address.encode())?;

        match bytes {
            None => Ok(SerializableCoin(Coin::zero())),
            Some(bytes) => {
                Ok(SerializableCoin::decode(&mut bytes.as_slice()).ok_or(ErrorKind::DeserializationError)?)
            }
        }
    }

    /// Changes balance for an address with given balance change
    pub fn change(&self, address: &ExtendedAddr, change: &BalanceChange) -> Result<SerializableCoin> {
        let current = self.get(address)?;
        let new = (current.inner() + change)?;

        self.storage.set(KEYSPACE, address.encode(), new.encode())?;

        Ok(SerializableCoin(new))
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
    use client_common::balance::BalanceChange;
    use client_common::serializable::SerializableCoin;
    use client_common::storage::MemoryStorage;

    #[test]
    fn check_flow() {
        let balance_service = BalanceService::new(MemoryStorage::default());
        let address = ExtendedAddr::BasicRedeem(Default::default());

        assert_eq!(SerializableCoin(Coin::zero()), balance_service.get(&address).unwrap());
        assert_eq!(
            SerializableCoin(Coin::new(30).unwrap()),
            balance_service
                .change(&address, &BalanceChange::Incoming(SerializableCoin(Coin::new(30).unwrap())))
                .unwrap()
        );
        assert_eq!(
            SerializableCoin(Coin::new(10).unwrap()),
            balance_service
                .change(&address, &BalanceChange::Outgoing(SerializableCoin(Coin::new(20).unwrap())))
                .unwrap()
        );
        assert_eq!(
            SerializableCoin(Coin::new(10).unwrap()),
            balance_service.get(&address).unwrap()
        );
        assert!(balance_service.clear().is_ok());
        assert_eq!(SerializableCoin(Coin::zero()), balance_service.get(&address).unwrap());
    }
}
