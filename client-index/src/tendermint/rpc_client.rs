use failure::ResultExt;
use jsonrpc::client::Client as JsonRpcClient;
use serde::Deserialize;
use serde_json::{json, Value};

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
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn check_genesis() {
//         let client = RpcClient::new("http://localhost:26657/");
//         let genesis = client.genesis().unwrap();
//         let transactions = genesis.transactions().unwrap();

//         println!("{:?}", transactions);

//         assert_eq!(1, transactions.len());
//     }
// }
