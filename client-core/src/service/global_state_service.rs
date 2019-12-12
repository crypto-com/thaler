use parity_scale_codec::{Decode, Encode};
use tendermint::validator;

use client_common::tendermint::lite;
use client_common::{ErrorKind, Result, ResultExt, Storage};

const KEYSPACE: &str = "core_global_state";

/// Global state for wallet
#[derive(Debug, Encode, Decode)]
pub struct GlobalState {
    /// last block height
    pub last_block_height: u64,
    /// last app hash
    pub last_app_hash: String,
    /// current trusted state for lite client verification
    pub trusted_state: lite::TrustedState,
}

impl GlobalState {
    /// construct genesis global state
    pub fn genesis(genesis_validators: Vec<validator::Info>) -> GlobalState {
        GlobalState {
            last_block_height: 0,
            last_app_hash: "".to_owned(),
            trusted_state: lite::TrustedState::genesis(genesis_validators),
        }
    }
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

    /// Updates last block height and last app hash with given values
    pub fn save_global_state(&self, name: &str, state: &GlobalState) -> Result<()> {
        self.storage.set(KEYSPACE, name, state.encode()).map(|_| ())
    }

    /// Deletes global state data for given wallet
    #[inline]
    pub fn delete_global_state(&self, name: &str) -> Result<()> {
        self.storage.delete(KEYSPACE, name).map(|_| ())
    }

    /// Clears all storage
    #[inline]
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }

    /// Get wallet global state
    pub fn get_global_state(&self, name: &str) -> Result<Option<GlobalState>> {
        if let Some(bytes) = self.storage.get(KEYSPACE, name)? {
            Ok(Some(GlobalState::decode(&mut bytes.as_slice()).chain(
                || {
                    (
                        ErrorKind::DeserializationError,
                        format!(
                            "Unable to deserialize global state for wallet with name {}",
                            name
                        ),
                    )
                },
            )?))
        } else {
            Ok(None)
        }
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

        assert!(global_state_service
            .get_global_state(name)
            .unwrap()
            .is_none());
        assert!(global_state_service
            .save_global_state(
                name,
                &GlobalState {
                    last_block_height: 5,
                    last_app_hash:
                        "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C"
                            .to_string(),
                    trusted_state: lite::TrustedState::genesis(vec![]),
                }
            )
            .is_ok());
        assert_eq!(
            5,
            global_state_service
                .get_global_state(name)
                .unwrap()
                .unwrap()
                .last_block_height
        );
        assert_eq!(
            "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C".to_string(),
            global_state_service
                .get_global_state(name)
                .unwrap()
                .unwrap()
                .last_app_hash
        );
        assert!(global_state_service.clear().is_ok());
        assert!(global_state_service
            .get_global_state(name)
            .unwrap()
            .is_none());
    }
}
