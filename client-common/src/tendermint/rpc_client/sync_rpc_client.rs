use std::{
    convert::TryFrom,
    sync::{mpsc::sync_channel, Arc},
    time::{Duration, SystemTime},
};

use itertools::izip;
use serde::Deserialize;
use serde_json::{json, Value};
use tendermint::{lite, validator};
use tokio::runtime::Runtime;

use chain_core::state::ChainState;

use super::async_rpc_client::AsyncRpcClient;
use crate::{
    tendermint::{lite::TrustedState, types::*, Client},
    Error, ErrorKind, Result, ResultExt,
};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Wraps asynchronous RPC client and executes it in tokio runtime
#[derive(Clone)]
pub struct SyncRpcClient {
    runtime: Arc<Runtime>,
    async_rpc_client: AsyncRpcClient,
}

impl SyncRpcClient {
    /// Creates a new synchronous websocket RPC client
    pub fn new(url: &str) -> Result<Self> {
        let mut runtime = Runtime::new().chain(|| {
            (
                ErrorKind::InitializationError,
                "Unable to start tokio runtime",
            )
        })?;

        let async_rpc_client = runtime
            .block_on(async { AsyncRpcClient::new(url).await })
            .chain(|| {
                (
                    ErrorKind::InitializationError,
                    format!("Unable to connect to tendermint RPC websocket at: {}", url),
                )
            })?;

        Ok(Self {
            runtime: Arc::new(runtime),
            async_rpc_client,
        })
    }

    /// Makes an RPC call and deserializes response
    pub fn call<T>(&self, method: &'static str, params: Vec<Value>) -> Result<T>
    where
        T: Send + 'static,
        for<'de> T: Deserialize<'de>,
    {
        let (sender, receiver) = sync_channel(1);
        let async_rpc_client = self.async_rpc_client.clone();

        self.runtime.spawn(async move {
            let response = async_rpc_client.call(method, &params).await;
            if let Err(e) = sender.send(response) {
                log::error!(
                    "Unable to send tendermint RPC response back to response channel: {}",
                    e
                );
            }
        });

        receiver
            .recv_timeout(RESPONSE_TIMEOUT)
            .chain(|| (ErrorKind::TendermintRpcError, "Request timed out"))?
            .chain(|| {
                (
                    ErrorKind::TendermintRpcError,
                    "Error while calling tendermint RPC call",
                )
            })
    }

    /// Makes RPC call in batch and deserializes responses
    pub fn call_batch<T>(&self, params: Vec<(&'static str, Vec<Value>)>) -> Result<Vec<T>>
    where
        T: Send + 'static,
        for<'de> T: Deserialize<'de>,
    {
        let (sender, receiver) = sync_channel(1);
        let async_rpc_client = self.async_rpc_client.clone();

        self.runtime.spawn(async move {
            let response = async_rpc_client.call_batch(&params).await;
            if let Err(e) = sender.send(response) {
                log::error!(
                    "Unable to send tendermint RPC response back to response channel: {}",
                    e
                );
            }
        });

        receiver
            .recv_timeout(RESPONSE_TIMEOUT)
            .chain(|| (ErrorKind::TendermintRpcError, "Request timed out"))?
            .chain(|| {
                (
                    ErrorKind::TendermintRpcError,
                    "Error while calling tendermint RPC call",
                )
            })
    }

    fn validators_batch<T: Iterator<Item = u64>>(
        &self,
        heights: T,
    ) -> Result<Vec<ValidatorsResponse>> {
        let params = heights
            .map(|height| {
                (
                    "validators",
                    vec![json!(height.to_string()), json!("0"), json!("100")],
                )
            })
            .collect::<Vec<(&str, Vec<Value>)>>();
        self.call_batch(params)
    }

    fn commit_batch<'a, T: Iterator<Item = &'a u64>>(
        &self,
        heights: T,
    ) -> Result<Vec<CommitResponse>> {
        let params = heights
            .map(|height| ("commit", vec![json!(height.to_string())]))
            .collect::<Vec<(&str, Vec<Value>)>>();
        self.call_batch(params)
    }
}

impl Client for SyncRpcClient {
    /// Makes `genesis` call to tendermint
    fn genesis(&self) -> Result<Genesis> {
        Ok(self
            .call::<GenesisResponse>("genesis", Default::default())?
            .genesis)
    }

    /// Makes `status` call to tendermint
    fn status(&self) -> Result<StatusResponse> {
        self.call("status", Default::default())
    }

    /// Makes `block` call to tendermint
    fn block(&self, height: u64) -> Result<Block> {
        let params = vec![json!(height.to_string())];
        Ok(self.call::<BlockResponse>("block", params)?.block)
    }

    /// Makes batched `block` call to tendermint
    fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, heights: T) -> Result<Vec<Block>> {
        let params = heights
            .map(|height| ("block", vec![json!(height.to_string())]))
            .collect::<Vec<(&'static str, Vec<Value>)>>();
        let rsps = self.call_batch::<BlockResponse>(params)?;
        Ok(rsps.into_iter().map(|rsp| rsp.block).collect())
    }

    /// Makes `block_results` call to tendermint
    fn block_results(&self, height: u64) -> Result<BlockResultsResponse> {
        let params = vec![json!(height.to_string())];
        self.call("block_results", params)
    }

    /// Makes batched `block_results` call to tendermint
    fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
        &self,
        heights: T,
    ) -> Result<Vec<BlockResultsResponse>> {
        let params = heights
            .map(|height| ("block_results", vec![json!(height.to_string())]))
            .collect::<Vec<(&'static str, Vec<Value>)>>();
        self.call_batch(params)
    }

    /// Fetch continuous blocks and verify them.
    fn block_batch_verified<'a, T: Clone + Iterator<Item = &'a u64>>(
        &self,
        mut state: TrustedState,
        heights: T,
    ) -> Result<(Vec<Block>, TrustedState)> {
        let commits = self.commit_batch(heights.clone())?;
        let validators: Vec<validator::Set> = self
            .validators_batch(heights.clone().map(|h| h.saturating_add(1)))?
            .into_iter()
            .map(|rsp| validator::Set::new(rsp.validators))
            .collect();
        let blocks = self.block_batch(heights)?;
        for (commit, next_vals, block) in izip!(&commits, &validators, &blocks) {
            let signed_header =
                lite::SignedHeader::new(commit.signed_header.clone(), block.header.clone());
            state = if let Some(state) = &state.0 {
                lite::verifier::verify_single(
                    state.clone(),
                    &signed_header,
                    state.validators(),
                    next_vals,
                    // FIXME make parameters configurable
                    lite::TrustThresholdFraction::new(1, 3).unwrap(),
                    Duration::from_secs(std::u32::MAX as u64),
                    SystemTime::now(),
                )
                .map_err(|err| {
                    Error::new(
                        ErrorKind::VerifyError,
                        format!("block verify failed: {:?}", err),
                    )
                })?
                .into()
            } else {
                // TODO verify block1 against genesis block
                lite::TrustedState::new(signed_header, next_vals.clone()).into()
            };
        }
        Ok((blocks, state))
    }

    /// Makes `broadcast_tx_sync` call to tendermint
    fn broadcast_transaction(&self, transaction: &[u8]) -> Result<BroadcastTxResponse> {
        let params = vec![json!(transaction)];
        let rsp = self.call::<BroadcastTxResponse>("broadcast_tx_sync", params)?;

        if rsp.code.is_err() {
            Err(Error::new(ErrorKind::TendermintRpcError, rsp.log.as_ref()))
        } else {
            Ok(rsp)
        }
    }

    /// Makes `abci_query` call to tendermint
    fn query(
        &self,
        path: &str,
        data: &[u8],
        height: Option<Height>,
        prove: bool,
    ) -> Result<AbciQuery> {
        let height = height
            .map(|h| i64::try_from(h.value()))
            .transpose()
            .err_kind(ErrorKind::InvalidInput, || "invalid height")?
            .unwrap_or(-1);
        let params = vec![
            json!(path),
            json!(hex::encode(data)),
            json!(height.to_string()),
            json!(prove),
        ];
        let result = self
            .call::<AbciQueryResponse>("abci_query", params)?
            .response;

        if result.code.is_err() {
            return Err(Error::new(
                ErrorKind::TendermintRpcError,
                result.log.to_string(),
            ));
        }

        Ok(result)
    }

    /// Match batch state `abci_query` call to tendermint
    fn query_state_batch<T: Iterator<Item = u64>>(&self, heights: T) -> Result<Vec<ChainState>> {
        let params: Vec<(&str, Vec<Value>)> = heights
            .map(|height| {
                (
                    "abci_query",
                    vec![
                        json!("state"),
                        json!(null),
                        json!(height.to_string()),
                        json!(null),
                    ],
                )
            })
            .collect();
        let rsps = self.call_batch::<AbciQueryResponse>(params)?;

        rsps.into_iter()
            .map(|rsp| {
                if let Some(value) = rsp.response.value {
                    let state = serde_json::from_str(
                        &String::from_utf8(value)
                            .chain(|| (ErrorKind::InvalidInput, "chain state decode failed"))?,
                    )
                    .chain(|| (ErrorKind::InvalidInput, "chain state decode failed"))?;
                    Ok(state)
                } else {
                    Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "abci query fail: {}, {}",
                            rsp.response.code.value(),
                            rsp.response.log,
                        ),
                    ))
                }
            })
            .collect()
    }
}
