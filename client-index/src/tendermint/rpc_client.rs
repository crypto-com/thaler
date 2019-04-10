use failure::ResultExt;
use jsonrpc::client::Client as JsonRpcClient;
use serde_json::json;

use client_common::{ErrorKind, Result};

use crate::tendermint::types::*;
use crate::tendermint::Client;

/// Tendermint RPC Client
pub struct RpcClient {
    inner: JsonRpcClient,
}

impl RpcClient {
    /// Creates a new instance of `RpcClient`
    pub fn new(url: &str) -> Self {
        let inner = JsonRpcClient::new(url.to_owned(), None, None);

        Self { inner }
    }
}

impl Client for RpcClient {
    fn genesis(&self) -> Result<Genesis> {
        let request = self.inner.build_request("genesis", Default::default());

        let response = self
            .inner
            .send_request(&request)
            .context(ErrorKind::RpcError)?;

        let result = response.result().context(ErrorKind::RpcError)?;

        Ok(result)
    }

    fn status(&self) -> Result<Status> {
        let request = self.inner.build_request("status", Default::default());

        let response = self
            .inner
            .send_request(&request)
            .context(ErrorKind::RpcError)?;

        let result = response.result().context(ErrorKind::RpcError)?;

        Ok(result)
    }

    fn block(&self, height: u64) -> Result<Block> {
        let params = [json!(height.to_string())];
        let request = self.inner.build_request("block", &params);

        let response = self
            .inner
            .send_request(&request)
            .context(ErrorKind::RpcError)?;

        let result = response.result().context(ErrorKind::RpcError)?;

        Ok(result)
    }

    fn block_results(&self, height: u64) -> Result<BlockResults> {
        let params = [json!(height.to_string())];
        let request = self.inner.build_request("block_results", &params);

        let response = self
            .inner
            .send_request(&request)
            .context(ErrorKind::RpcError)?;

        let result = response.result().context(ErrorKind::RpcError)?;

        Ok(result)
    }
}
