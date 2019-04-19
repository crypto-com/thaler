#![cfg(feature = "rpc")]

use std::sync::Arc;

use failure::ResultExt;
use jsonrpc::client::Client as JsonRpcClient;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tendermint::types::*;
use crate::tendermint::Client;
use crate::{ErrorKind, Result};

/// Tendermint RPC Client
#[derive(Clone)]
pub struct RpcClient {
    inner: Arc<JsonRpcClient>,
}

impl RpcClient {
    /// Creates a new instance of `RpcClient`
    pub fn new(url: &str) -> Self {
        let inner = Arc::new(JsonRpcClient::new(url.to_owned(), None, None));

        Self { inner }
    }

    fn call<T>(&self, name: &str, params: &[Value]) -> Result<T>
    where
        for<'de> T: Deserialize<'de>,
    {
        let request = self.inner.build_request(name, params);

        let response = self
            .inner
            .send_request(&request)
            .context(ErrorKind::RpcError)?;

        let result = response.result::<T>().context(ErrorKind::RpcError)?;

        Ok(result)
    }
}

impl Client for RpcClient {
    fn genesis(&self) -> Result<Genesis> {
        self.call("genesis", Default::default())
    }

    fn status(&self) -> Result<Status> {
        self.call("status", Default::default())
    }

    fn block(&self, height: u64) -> Result<Block> {
        let params = [json!(height.to_string())];
        self.call("block", &params)
    }

    fn block_results(&self, height: u64) -> Result<BlockResults> {
        let params = [json!(height.to_string())];
        self.call("block_results", &params)
    }

    fn broadcast_transaction(&self, transaction: &[u8]) -> Result<()> {
        let params = [json!(transaction)];
        self.call::<serde_json::Value>("broadcast_tx_sync", &params)
            .map(|_| ())
    }
}

// Note: Do not delete these lines before writing integration tests.
// #[cfg(test)]
// mod tests {
//     use super::*;

//     use hex::decode;

//     #[test]
//     fn check_genesis() {
//         let transaction = decode("f89580f84ae3e2a04bf56f95da00be5479c212f9860ade019f00751014368bab2238bab08b9a6d9480e1e0d680940b65e1abbe69940639f2bdbf9f248e6c95d81811880000e8890423c78ac381abc0f846f8448001b840c361fe29c9ef2b02c367ceb5626ed2a9ad6cccd8dc74ce5fbfe81864a5e39f581df262f2041ffc57283ea908e4da877459281e29f580fadc2aff3a04a836a603").unwrap();

//         let client = RpcClient::new("http://localhost:26657/");
//         let broadcast = client.broadcast_transaction(&transaction);
//         assert!(broadcast.is_ok());
//     }
// }
