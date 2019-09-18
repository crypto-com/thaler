use parity_scale_codec::{Decode, Encode};
use secstr::SecUtf8;

use client_common::{ErrorKind, Result, ResultExt, SecureStorage, Storage};

const KEYSPACE: &str = "core_global_state";

#[derive(Debug, Default, Encode, Decode)]
struct GlobalState {
    last_block_height: u64,
    last_app_hash: String,
}

/// Exposes functionalities for managing client's global state (for synchronization)
///
/// Stores `wallet-name -> global-state`
#[derive(Default, Clone)]
pub struct GlobalStateService<S>
where
    S: Storage,
{
    storage: S,
}

impl<S> GlobalStateService<S>
where
    S: Storage,
{
    /// Creates new instance of global state service
    #[inline]
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Returns currently stored last block height for given wallet
    #[inline]
    pub fn last_block_height(&self, name: &str, passphrase: &SecUtf8) -> Result<u64> {
        self.get_global_state(name, passphrase)
            .map(|state| state.last_block_height)
    }

    /// Returns currently stored last app hash for given wallet
    #[inline]
    pub fn last_app_hash(&self, name: &str, passphrase: &SecUtf8) -> Result<String> {
        self.get_global_state(name, passphrase)
            .map(|state| state.last_app_hash)
    }

    /// Updates last block height and last app hash with given values
    pub fn set_global_state(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        last_block_height: u64,
        last_app_hash: String,
    ) -> Result<()> {
        let global_state = GlobalState {
            last_block_height,
            last_app_hash,
        };

        self.storage
            .set_secure(KEYSPACE, name, global_state.encode(), passphrase)
            .map(|_| ())
    }

    /// Deletes global state data for given wallet
    #[inline]
    pub fn delete_global_state(&self, name: &str, passphrase: &SecUtf8) -> Result<()> {
        // To check if name and passphrase is correct
        let _ = self.last_block_height(name, passphrase)?;
        self.storage.delete(KEYSPACE, name).map(|_| ())
    }

    /// Clears all storage
    #[inline]
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }

    fn get_global_state(&self, name: &str, passphrase: &SecUtf8) -> Result<GlobalState> {
        self.storage
            .get_secure(KEYSPACE, name, passphrase)
            .and_then(|bytes_optional| {
                bytes_optional
                    .map(|bytes| {
                        GlobalState::decode(&mut bytes.as_slice()).chain(|| {
                            (
                                ErrorKind::DeserializationError,
                                format!(
                                    "Unable to deserialize global state for wallet with name {}",
                                    name
                                ),
                            )
                        })
                    })
                    .transpose()
                    .map(|global_state_optional| global_state_optional.unwrap_or_default())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use client_common::storage::MemoryStorage;

    #[test]
    fn check_flow() {
        let storage = MemoryStorage::default();
        let global_state_service = GlobalStateService::new(storage);

        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        assert_eq!(
            0,
            global_state_service
                .last_block_height(name, passphrase)
                .unwrap()
        );
        assert!(global_state_service
            .set_global_state(
                name,
                passphrase,
                5,
                "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C".to_string(),
            )
            .is_ok());
        assert_eq!(
            5,
            global_state_service
                .last_block_height(name, passphrase)
                .unwrap()
        );
        assert_eq!(
            "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C".to_string(),
            global_state_service
                .last_app_hash(name, passphrase)
                .unwrap()
        );
        assert!(global_state_service.clear().is_ok());
        assert_eq!(
            0,
            global_state_service
                .last_block_height(name, passphrase)
                .unwrap()
        );
    }
}
