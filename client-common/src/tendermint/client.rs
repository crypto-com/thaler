use crate::tendermint::lite;
use crate::tendermint::types::*;
use crate::Result;
use chain_core::state::ChainState;

/// Makes remote calls to tendermint (backend agnostic)
pub trait Client: Send + Sync {
    /// Makes `genesis` call to tendermint
    fn genesis(&self) -> Result<Genesis>;

    /// Makes `status` call to tendermint
    fn status(&self) -> Result<Status>;

    /// Makes `block` call to tendermint
    fn block(&self, height: u64) -> Result<Block>;

    /// Makes batched `block` call to tendermint
    fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, heights: T) -> Result<Vec<Block>>;

    /// Makes `block_results` call to tendermint
    fn block_results(&self, height: u64) -> Result<BlockResults>;

    /// Makes batched `block_results` call to tendermint
    fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
        &self,
        heights: T,
    ) -> Result<Vec<BlockResults>>;

    /// Fetch continuous blocks and verify them.
    fn block_batch_verified<'a, T: Clone + Iterator<Item = &'a u64>>(
        &self,
        _state: lite::TrustedState,
        _heights: T,
    ) -> Result<(Vec<Block>, lite::TrustedState)>;

    /// Makes `broadcast_tx_sync` call to tendermint
    fn broadcast_transaction(&self, transaction: &[u8]) -> Result<BroadcastTxResponse>;

    /// Makes `abci_query` call to tendermint
    fn query(&self, path: &str, data: &[u8]) -> Result<AbciQuery>;

    /// Match batch state `abci_query` call to tendermint
    fn query_state_batch<T: Iterator<Item = u64>>(&self, heights: T) -> Result<Vec<ChainState>>;
}
