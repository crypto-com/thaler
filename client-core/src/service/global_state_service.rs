use parity_scale_codec::{Decode, Encode};

use client_common::{ErrorKind, PublicKey, Result, ResultExt, Storage};

const KEYSPACE: &str = "index_global_state";

#[derive(Debug, Encode, Decode)]
struct GlobalState {
    last_block_height: u64,
    last_app_hash: String,
}

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

    /// Returns currently stored last block height for given view key
    pub fn last_block_height(&self, view_key: &PublicKey) -> Result<u64> {
        let global_state_optional = self.storage.get(KEYSPACE, view_key.encode())?;

        match global_state_optional {
            None => Ok(0),
            Some(bytes) => GlobalState::decode(&mut bytes.as_slice())
                .map(|global_state| global_state.last_block_height)
                .chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        format!(
                            "Unable to deserialize global state for view key: {}",
                            view_key
                        ),
                    )
                }),
        }
    }

    /// Returns currently stored last app hash for given view key
    pub fn last_app_hash(&self, view_key: &PublicKey) -> Result<String> {
        let global_state_optional = self.storage.get(KEYSPACE, view_key.encode())?;

        match global_state_optional {
            None => Ok("".to_string()),
            Some(bytes) => GlobalState::decode(&mut bytes.as_slice())
                .map(|global_state| global_state.last_app_hash)
                .chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        format!(
                            "Unable to deserialize global state for view key: {}",
                            view_key
                        ),
                    )
                }),
        }
    }

    /// Updates last block height and last app hash with given values
    pub fn set_global_state(
        &self,
        view_key: &PublicKey,
        last_block_height: u64,
        last_app_hash: String,
    ) -> Result<()> {
        let global_state = GlobalState {
            last_block_height,
            last_app_hash,
        };

        self.storage
            .set(KEYSPACE, view_key.encode(), global_state.encode())
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
            .set_global_state(
                &public_key,
                5,
                "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C".to_string(),
            )
            .is_ok());
        assert_eq!(
            5,
            global_state_service.last_block_height(&public_key).unwrap()
        );
        assert_eq!(
            "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C".to_string(),
            global_state_service.last_app_hash(&public_key).unwrap()
        );
        assert!(global_state_service.clear().is_ok());
        assert_eq!(
            0,
            global_state_service.last_block_height(&public_key).unwrap()
        );
    }
}
