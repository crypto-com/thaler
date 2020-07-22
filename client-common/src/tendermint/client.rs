use crate::tendermint::types::*;
use crate::Result;
use chain_core::state::ChainState;

/// Makes remote calls to tendermint (backend agnostic)
pub trait Client: Send + Sync + Clone {
    /// Makes `genesis` call to tendermint
    fn genesis(&self) -> Result<Genesis>;

    /// Makes `status` call to tendermint
    fn status(&self) -> Result<StatusResponse>;

    /// Makes `block` call to tendermint
    fn block(&self, height: u64) -> Result<Block>;

    /// Makes batched `block` call to tendermint
    fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, heights: T) -> Result<Vec<Block>>;

    /// Makes `block_results` call to tendermint
    fn block_results(&self, height: u64) -> Result<BlockResultsResponse>;

    /// Makes batched `block_results` call to tendermint
    fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
        &self,
        heights: T,
    ) -> Result<Vec<BlockResultsResponse>>;

    /// Makes `broadcast_tx_sync` call to tendermint
    fn broadcast_transaction(&self, transaction: &[u8]) -> Result<BroadcastTxResponse>;

    /// Makes `abci_query` call to tendermint
    ///
    /// height: `None` means latest
    /// prove: Include proofs of the transactions inclusion in the block
    fn query(
        &self,
        path: &str,
        data: &[u8],
        height: Option<Height>,
        prove: bool,
    ) -> Result<AbciQuery>;

    /// Match batch state `abci_query` call to tendermint
    fn query_state_batch<T: Iterator<Item = u64>>(&self, heights: T) -> Result<Vec<ChainState>>;
}
