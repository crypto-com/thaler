use parity_scale_codec::{Decode, Encode};
use tendermint::validator;

use client_common::tendermint::lite;
use client_common::{ErrorKind, Result, ResultExt, Storage};

/// key space of wallet sync state
const KEYSPACE: &str = "core_wallet_sync";

/// Sync state for wallet
#[derive(Debug, Encode, Decode)]
pub struct SyncState {
    /// last block height
    pub last_block_height: u64,
    /// last app hash
    pub last_app_hash: String,
    /// current trusted state for lite client verification
    pub trusted_state: lite::TrustedState,
}

impl SyncState {
    /// construct genesis global state
    pub fn genesis(genesis_validators: Vec<validator::Info>) -> SyncState {
        SyncState {
            last_block_height: 0,
            last_app_hash: "".to_owned(),
            trusted_state: lite::TrustedState::genesis(genesis_validators),
        }
    }
}

/// Load sync state from storage
pub fn load_sync_state<S: Storage>(storage: &S, name: &str) -> Result<Option<SyncState>> {
    storage.load(KEYSPACE, name)
}

/// Save sync state from storage
pub fn save_sync_state<S: Storage>(storage: &S, name: &str, state: &SyncState) -> Result<()> {
    storage.save(KEYSPACE, name, state)
}

/// Delete sync state from storage
pub fn delete_sync_state<S: Storage>(storage: &S, name: &str) -> Result<()> {
    storage.delete(KEYSPACE, name)?;
    Ok(())
}

/// Exposes functionalities for managing client's global state (for synchronization)
///
/// Stores `wallet-name -> global-state`
#[derive(Debug, Default, Clone)]
pub struct SyncStateService<S>
where
    S: Storage,
{
    storage: S,
}

impl<S> SyncStateService<S>
where
    S: Storage,
{
    /// Creates new instance of global state service
    #[inline]
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Updates last block height and last app hash with given values
    pub fn save_global_state(&self, name: &str, state: &SyncState) -> Result<()> {
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
    pub fn get_global_state(&self, name: &str) -> Result<Option<SyncState>> {
        if let Some(bytes) = self.storage.get(KEYSPACE, name)? {
            Ok(Some(SyncState::decode(&mut bytes.as_slice()).chain(
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
    use serde_json;

    use super::*;
    use client_common::storage::MemoryStorage;

    #[test]
    fn check_flow() {
        let storage = MemoryStorage::default();
        let global_state_service = SyncStateService::new(storage);

        let name = "name";

        assert!(global_state_service
            .get_global_state(name)
            .unwrap()
            .is_none());
        assert!(global_state_service
            .save_global_state(
                name,
                &SyncState {
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

    #[test]
    fn check_sync_state_serialization() {
        let trusted_state_json = r#"{"header":{"version":{"block":"10","app":"0"},"chain_id":"test-chain-y3m1e6-AB","height":"1","time":"2019-11-20T08:56:48.618137Z","num_txs":"0","total_txs":"0","last_block_id":null,"last_commit_hash":null,"data_hash":null,"validators_hash":"1D19568662F9A9167B338F98C860C4102AA0DE85600BF48A15B192DB53D030A1","next_validators_hash":"1D19568662F9A9167B338F98C860C4102AA0DE85600BF48A15B192DB53D030A1","consensus_hash":"048091BC7DDC283F77BFBF91D73C44DA58C3DF8A9CBC867405D8B7F3DAADA22F","app_hash":"0F46E113C21F9EACB26D752F9523746CF8D47ECBEA492736D176005911F973A5","last_results_hash":null,"evidence_hash":null,"proposer_address":"A59B92278703DFECE52A40D9EF3AE9D1EDC6B949"},"validators":{"validators":[{"address":"A59B92278703DFECE52A40D9EF3AE9D1EDC6B949","pub_key":{"type":"tendermint/PubKeyEd25519","value":"oblY1MjCzNuYlr7A5cUsEY3yBxYBSRHzha16wbnWNx8="},"voting_power":"5000000000","proposer_priority":"0"}]}}"#;
        let mut state = SyncState::genesis(vec![]);
        state.last_block_height = 1;
        state.last_app_hash =
            "0F46E113C21F9EACB26D752F9523746CF8D47ECBEA492736D176005911F973A5".to_owned();
        state.trusted_state = serde_json::from_str(trusted_state_json).unwrap();

        let key = "Default";

        let storage = MemoryStorage::default();
        storage.save(KEYSPACE, key, &state).unwrap();
        let state1: SyncState = storage.load(KEYSPACE, key).unwrap().unwrap();

        assert_eq!(state.encode(), state1.encode());
    }
}
