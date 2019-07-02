use crate::tendermint::types::QueryResult;
use crate::tendermint::types::*;
use crate::Result;
use chain_core::state::account::StakedState;

/// Makes remote calls to tendermint (backend agnostic)
pub trait Client: Send + Sync {
    /// Makes `genesis` call to tendermint
    fn genesis(&self) -> Result<Genesis>;

    /// Makes `status` call to tendermint
    fn status(&self) -> Result<Status>;

    /// Makes `block` call to tendermint
    fn block(&self, height: u64) -> Result<Block>;

    /// Makes `block_results` call to tendermint
    fn block_results(&self, height: u64) -> Result<BlockResults>;

    /// Makes `broadcast_tx_sync` call to tendermint
    fn broadcast_transaction(&self, transaction: &[u8]) -> Result<()>;

    /// Get staked-state from the staked stake address
    fn get_account(&self, staked_state_address: &[u8]) -> Result<StakedState>;

    /// Get abci query
    fn query(&self, path: &str, data: &str) -> Result<QueryResult>;
}
