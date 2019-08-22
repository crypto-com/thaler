#![cfg(feature = "rpc")]

use failure::{format_err, ResultExt};
use jsonrpc::client::Client as JsonRpcClient;
use jsonrpc::Request;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tendermint::types::*;
use crate::tendermint::Client;
use crate::{Error, ErrorKind, Result};

/// Tendermint RPC Client
#[derive(Clone)]
pub struct RpcClient {
    url: String,
}

impl RpcClient {
    /// Creates a new instance of `RpcClient`
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
        }
    }

    fn call<T>(&self, name: &str, params: &[Value]) -> Result<T>
    where
        for<'de> T: Deserialize<'de>,
    {
        // jsonrpc does not handle Hyper connection reset properly. The current
        // inefficient workaround is to create a new client on every call.
        // https://github.com/apoelstra/rust-jsonrpc/issues/26
        let client = JsonRpcClient::new(self.url.to_owned(), None, None);
        let request = client.build_request(name, params);
        let response = client.send_request(&request).context(ErrorKind::RpcError)?;

        let result = response.result::<T>().context(ErrorKind::RpcError)?;
        Ok(result)
    }

    fn call_batch<T>(&self, params: &[(&str, Vec<Value>)]) -> Result<Vec<Option<T>>>
    where
        for<'de> T: Deserialize<'de>,
    {
        if params.is_empty() {
            // Do not send empty batch requests
            return Ok(Default::default());
        }

        if params.len() == 1 {
            // Do not send batch request when there is only one set of params
            self.call::<T>(params[0].0, &params[0].1)
                .map(|value| vec![Some(value)])
        } else {
            // jsonrpc does not handle Hyper connection reset properly. The current
            // inefficient workaround is to create a new client on every call.
            // https://github.com/apoelstra/rust-jsonrpc/issues/26
            let client = JsonRpcClient::new(self.url.to_owned(), None, None);
            let requests = params
                .iter()
                .map(|(name, params)| client.build_request(name, params))
                .collect::<Vec<Request>>();
            let responses = client.send_batch(&requests).context(ErrorKind::RpcError)?;
            responses
                .into_iter()
                .map(|response| -> Result<Option<T>> {
                    response
                        .map(|inner| -> Result<T> {
                            inner
                                .result::<T>()
                                .context(ErrorKind::RpcError)
                                .map_err(Into::into)
                        })
                        .transpose()
                })
                .collect::<Result<Vec<Option<T>>>>()
        }
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

    fn block_batch<T: Iterator<Item = u64>>(&self, heights: T) -> Result<Vec<Block>> {
        let params = heights
            .map(|height| ("block", vec![json!(height.to_string())]))
            .collect::<Vec<(&str, Vec<Value>)>>();
        let response = self.call_batch::<Block>(&params)?;

        response
            .into_iter()
            .map(|block| {
                block.ok_or_else(|| -> Error {
                    format_err!("Block information not found")
                        .context(ErrorKind::RpcError)
                        .into()
                })
            })
            .collect::<Result<Vec<Block>>>()
    }

    fn block_results(&self, height: u64) -> Result<BlockResults> {
        let params = [json!(height.to_string())];
        self.call("block_results", &params)
    }

    fn block_results_batch<T: Iterator<Item = u64>>(
        &self,
        heights: T,
    ) -> Result<Vec<BlockResults>> {
        let params = heights
            .map(|height| ("block_results", vec![json!(height.to_string())]))
            .collect::<Vec<(&str, Vec<Value>)>>();
        let response = self.call_batch::<BlockResults>(&params)?;

        response
            .into_iter()
            .map(|block_results| {
                block_results.ok_or_else(|| -> Error {
                    format_err!("Block information not found")
                        .context(ErrorKind::RpcError)
                        .into()
                })
            })
            .collect::<Result<Vec<BlockResults>>>()
    }

    fn broadcast_transaction(&self, transaction: &[u8]) -> Result<BroadcastTxResult> {
        let params = [json!(transaction)];
        self.call::<BroadcastTxResult>("broadcast_tx_sync", &params)
            .and_then(|result| {
                if result.code != 0 {
                    return Err(Error::from(ErrorKind::TransactionValidationFailed));
                }
                Ok(result)
            })
    }

    fn query(&self, path: &str, data: &[u8]) -> Result<QueryResult> {
        let params = [
            json!(path),
            json!(hex::encode(data)),
            json!(null),
            json!(null),
        ];
        self.call("abci_query", &params)
    }
}
