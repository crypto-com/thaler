use failure::ResultExt;
use rlp::{decode, encode};

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::balance::BalanceChange;
use client_common::{ErrorKind, Result, Storage};

const KEYSPACE: &str = "index_balance";

/// Exposes functionalities for managing balances
///
/// Stores `address -> balance` mapping
pub struct BalanceService<S> {
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
    pub fn get(&self, address: &ExtendedAddr) -> Result<Coin> {
        let bytes = self.storage.get(KEYSPACE, encode(address))?;

        match bytes {
            None => Ok(Coin::zero()),
            Some(bytes) => Ok(decode(&bytes).context(ErrorKind::DeserializationError)?),
        }
    }

    /// Changes balance for an address with given balance change
    pub fn change(&self, address: &ExtendedAddr, change: &BalanceChange) -> Result<Coin> {
        let current = self.get(address)?;
        let new = (current + change)?;

        self.storage.set(KEYSPACE, encode(address), encode(&new))?;

        Ok(new)
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}
