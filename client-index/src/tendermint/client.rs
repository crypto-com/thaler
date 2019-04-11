use client_common::Result;

use crate::tendermint::types::*;

/// Makes remote calls to tendermint (backend agnostic)
pub trait Client {
    /// Makes `genesis` call to tendermint
    fn genesis(&self) -> Result<Genesis>;

    /// Makes `status` call to tendermint
    fn status(&self) -> Result<Status>;

    /// Makes `block` call to tendermint
    fn block(&self, height: u64) -> Result<Block>;

    /// Makes `block_results` call to tendermint
    fn block_results(&self, height: u64) -> Result<BlockResults>;
}
