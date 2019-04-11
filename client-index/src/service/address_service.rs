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
