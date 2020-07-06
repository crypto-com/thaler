use crate::{
    tendermint::{types::*, Client},
    ErrorKind, Result,
};
use chain_core::state::ChainState;

/// `Client` which returns `PermissionDenied` error for each function call.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnauthorizedClient;

impl Client for UnauthorizedClient {
    fn genesis(&self) -> Result<Genesis> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn status(&self) -> Result<StatusResponse> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn block(&self, _height: u64) -> Result<Block> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, _heights: T) -> Result<Vec<Block>> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn block_results(&self, _height: u64) -> Result<BlockResultsResponse> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
        &self,
        _heights: T,
    ) -> Result<Vec<BlockResultsResponse>> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<BroadcastTxResponse> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn query(
        &self,
        _path: &str,
        _data: &[u8],
        _height: Option<Height>,
        _prove: bool,
    ) -> Result<AbciQuery> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn query_state_batch<T: Iterator<Item = u64>>(&self, _heights: T) -> Result<Vec<ChainState>> {
        Err(ErrorKind::PermissionDenied.into())
    }
}
