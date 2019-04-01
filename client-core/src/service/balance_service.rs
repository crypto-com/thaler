use byteorder::{ByteOrder, LittleEndian};
use failure::ResultExt;

use chain_core::init::coin::Coin;

use crate::{Chain, Error, ErrorKind, Result, SecureStorage, Storage};

/// Exposes functionalities for transaction storage and syncing
#[derive(Default)]
pub struct BalanceService<C, T> {
    chain: C,
    storage: T,
}

impl<C, T> BalanceService<C, T>
where
    C: Chain,
    T: Storage,
{
    /// Creates a new instance of transaction service.
    pub fn new(chain: C, storage: T) -> Self {
        Self { chain, storage }
    }

    /// Updates balance after querying new transactions from Crypto.com Chain.
    pub fn sync(&self, wallet_id: &str, passphrase: &str, addresses: Vec<String>) -> Result<Coin> {
        let bytes = self
            .storage
            .get_secure(wallet_id.as_bytes(), passphrase.as_bytes())?;

        let mut storage_unit = match bytes {
            None => Default::default(),
            Some(bytes) => StorageUnit::deserialize_from(&bytes)?,
        };

        let (transaction_changes, block_height) = self
            .chain
            .query_transaction_changes(addresses, storage_unit.last_block_height)?;

        storage_unit.last_block_height = block_height;

        for change in transaction_changes {
            storage_unit.balance = (storage_unit.balance + change)?;
        }

        self.storage.set_secure(
            wallet_id.as_bytes(),
            storage_unit.serialize(),
            passphrase.as_bytes(),
        )?;

        Ok(storage_unit.balance)
    }

    /// Updates balance after querying all transactions from Crypto.com Chain.
    ///
    /// # Warning
    /// This should only be used when you need to recalculate balance from whole history of blockchain.
    pub fn sync_all(
        &self,
        wallet_id: &str,
        passphrase: &str,
        addresses: Vec<String>,
    ) -> Result<Coin> {
        let bytes = self
            .storage
            .get_secure(wallet_id.as_bytes(), passphrase.as_bytes())?;

        let mut storage_unit = match bytes {
            None => Default::default(),
            Some(bytes) => StorageUnit::deserialize_from(&bytes)?,
        };

        let (transaction_changes, block_height) =
            self.chain.query_transaction_changes(addresses, 0)?;

        storage_unit.last_block_height = block_height;

        for change in transaction_changes {
            storage_unit.balance = (storage_unit.balance + change)?;
        }

        self.storage.set_secure(
            wallet_id.as_bytes(),
            storage_unit.serialize(),
            passphrase.as_bytes(),
        )?;

        Ok(storage_unit.balance)
    }

    /// Returns balance for a given wallet ID.
    pub fn get_balance(&self, wallet_id: &str, passphrase: &str) -> Result<Option<Coin>> {
        let bytes = self
            .storage
            .get_secure(wallet_id.as_bytes(), passphrase.as_bytes())?;

        match bytes {
            None => Ok(None),
            Some(bytes) => {
                let storage_unit = StorageUnit::deserialize_from(&bytes)?;
                Ok(Some(storage_unit.balance))
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub(self) struct StorageUnit {
    pub(self) balance: Coin,
    pub(self) last_block_height: u64,
}

impl StorageUnit {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: [u8; 16] = [0; 16];

        LittleEndian::write_u64(&mut bytes[0..8], *self.balance);
        LittleEndian::write_u64(&mut bytes[8..16], self.last_block_height);

        bytes.to_vec()
    }

    pub fn deserialize_from(bytes: &[u8]) -> Result<StorageUnit> {
        if 16 != bytes.len() {
            Err(Error::from(ErrorKind::DeserializationError))
        } else {
            Ok(StorageUnit {
                balance: Coin::new(LittleEndian::read_u64(&bytes[0..8]))
                    .context(ErrorKind::DeserializationError)?,
                last_block_height: LittleEndian::read_u64(&bytes[8..16]),
            })
        }
    }
}

impl Default for StorageUnit {
    fn default() -> Self {
        StorageUnit {
            balance: Coin::zero(),
            last_block_height: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_unit_serialization() {
        let storage_unit = StorageUnit::default();

        let bytes = storage_unit.serialize();
        let new_storage_unit =
            StorageUnit::deserialize_from(&bytes).expect("Unable to deserialize");

        assert_eq!(
            storage_unit, new_storage_unit,
            "Serialization / deserialization implemented incorrectly"
        );
    }

    #[test]
    fn storage_unit_serialization_failure() {
        let storage_unit = StorageUnit::default();

        let bytes = storage_unit.serialize();
        let error =
            StorageUnit::deserialize_from(&bytes[0..15]).expect_err("Deserialized incorrect value");

        assert_eq!(
            error.kind(),
            ErrorKind::DeserializationError,
            "Invalid error type"
        );
    }
}
