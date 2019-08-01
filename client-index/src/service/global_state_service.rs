use failure::ResultExt;
use parity_scale_codec::{Decode, Encode};

use client_common::{ErrorKind, PublicKey, Result, Storage};

const KEYSPACE: &str = "index_global_state";

/// Exposes functionalities for managing client's global state
///
/// Stores `view_key -> last_block_height`
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

    /// Returns currently stored last block height
    pub fn last_block_height(&self, view_key: &PublicKey) -> Result<u64> {
        let last_block_height_optional = self.storage.get(KEYSPACE, view_key.encode())?;

        match last_block_height_optional {
            None => Ok(0),
            Some(bytes) => u64::decode(&mut bytes.as_slice())
                .context(ErrorKind::DeserializationError)
                .map_err(Into::into),
        }
    }

    /// Updates last block height with given value and returns old value
    pub fn set_last_block_height(
        &self,
        view_key: &PublicKey,
        last_block_height: u64,
    ) -> Result<()> {
        self.storage
            .set(KEYSPACE, view_key.encode(), last_block_height.encode())
            .map(|_| ())
    }

    /// Clears all storage
    #[inline]
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use client_common::storage::MemoryStorage;
    use client_common::PrivateKey;

    #[test]
    fn check_flow() {
        let storage = MemoryStorage::default();
        let global_state_service = GlobalStateService::new(storage);

        let private_key = PrivateKey::new().unwrap();
        let public_key = PublicKey::from(&private_key);

        assert_eq!(
            0,
            global_state_service.last_block_height(&public_key).unwrap()
        );
        assert!(global_state_service
            .set_last_block_height(&public_key, 5)
            .is_ok());
        assert_eq!(
            5,
            global_state_service.last_block_height(&public_key).unwrap()
        );
        assert!(global_state_service.clear().is_ok());
        assert_eq!(
            0,
            global_state_service.last_block_height(&public_key).unwrap()
        );
    }
}
