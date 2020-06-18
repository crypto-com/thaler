use std::{
    convert::TryFrom,
    sync::{mpsc::sync_channel, Arc},
    time::{Duration, SystemTime},
};

use itertools::izip;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde_json::{json, Value};
use tendermint::{lite, validator};
use tokio::runtime::Runtime;

use chain_core::state::ChainState;
use std::sync::Mutex;

use super::async_rpc_client::AsyncRpcClient;
use crate::{
    tendermint::{lite::TrustedState, types::*, Client},
    Error, ErrorKind, PrivateKey, Result, ResultExt, SignedTransaction, Transaction,
    TransactionObfuscation,
};

#[cfg(not(feature = "mock-enclave"))]
use crate::cipher::DefaultTransactionObfuscation;
#[cfg(not(feature = "mock-enclave"))]
type AppTransactionObfuscation = DefaultTransactionObfuscation;
#[cfg(feature = "mock-enclave")]
use crate::cipher::MockAbciTransactionObfuscation;
#[cfg(feature = "mock-enclave")]
use crate::tendermint::WebsocketRpcClient;
#[cfg(feature = "mock-enclave")]
type AppTransactionObfuscation = MockAbciTransactionObfuscation<WebsocketRpcClient>;
use chain_core::init::coin::CoinError;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::{Fee, FeeAlgorithm, LinearFee};
use chain_core::tx::TxAux;
use futures_util::sink::SinkExt;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Wraps asynchronous RPC client and executes it in tokio runtime
#[derive(Clone)]
pub struct SyncRpcClient {
    runtime: Arc<Mutex<Runtime>>,
    /// ASYNC RPC CLIENT
    pub async_rpc_client: Arc<Mutex<Option<AsyncRpcClient>>>,
    url: String,
}

impl FeeAlgorithm for SyncRpcClient {
    fn calculate_fee(&self, num_bytes: usize) -> std::result::Result<Fee, CoinError> {
        self.get_fee_policy().calculate_fee(num_bytes)
    }

    fn calculate_for_txaux(&self, txaux: &TxAux) -> std::result::Result<Fee, CoinError> {
        self.get_fee_policy().calculate_for_txaux(txaux)
    }
}

impl TransactionObfuscation for SyncRpcClient {
    fn decrypt(
        &self,
        transaction_ids: &[TxId],
        private_key: &PrivateKey,
    ) -> Result<Vec<Transaction>> {
        let obfuscator = self.get_tx_query().map_err(|e| Error::new(e.0, e.1))?;
        obfuscator.decrypt(transaction_ids, private_key)
    }

    fn encrypt(&self, transaction: SignedTransaction) -> Result<TxAux> {
        let obfuscator = self.get_tx_query().map_err(|e| Error::new(e.0, e.1))?;
        obfuscator.encrypt(transaction)
    }
}

impl SyncRpcClient {
    /// Creates a new synchronous websocket RPC client
    pub fn new(url: &str) -> Result<Self> {
        let runtime = Runtime::new().chain(|| {
            (
                ErrorKind::InitializationError,
                "Unable to start tokio runtime",
            )
        })?;

        Ok(Self {
            runtime: Arc::new(Mutex::new(runtime)),
            async_rpc_client: Arc::new(Mutex::new(None)),
            url: url.to_string(),
        })
    }

    /// get the fee policy
    pub fn get_fee_policy(&self) -> LinearFee {
        static POLICY: OnceCell<LinearFee> = OnceCell::new();
        let policy = POLICY.get_or_init(|| {
            self.genesis()
                .map_err(|e| log::error!("get genesis failed: {:?}", e))
                .expect("get tendermint genesis")
                .fee_policy()
        });
        *policy
    }

    /// get the obfuscation from tx query
    pub fn get_tx_query(
        &self,
    ) -> std::result::Result<impl TransactionObfuscation, (ErrorKind, String)> {
        static OBFUSCATION: OnceCell<
            std::result::Result<AppTransactionObfuscation, (ErrorKind, String)>,
        > = OnceCell::new();
        let obfuscation = OBFUSCATION.get_or_init(|| {
            AppTransactionObfuscation::from_tx_query(self)
                .map_err(|e| (e.kind(), e.message().into()))
        });
        obfuscation.clone()
    }

    fn get_async_client(&self) -> Result<AsyncRpcClient> {
        let mut maybe_rpc_client = self.async_rpc_client.lock().unwrap();
        if maybe_rpc_client.is_some() {
            return Ok(maybe_rpc_client.clone().unwrap());
        }
        let mut runtime = self.runtime.lock().unwrap();
        let async_rpc_client = runtime
            .block_on(async { AsyncRpcClient::new(&self.url).await })
            .chain(|| {
                (
                    ErrorKind::InitializationError,
                    format!(
                        "Unable to connect to tendermint RPC websocket at: {}",
                        self.url
                    ),
                )
            })?;
        *maybe_rpc_client = Some(async_rpc_client.clone());
        Ok(async_rpc_client)
    }

    /// Makes an RPC call and deserializes response
    pub fn call<T>(&self, method: &'static str, params: Vec<Value>) -> Result<T>
    where
        T: Send + 'static,
        for<'de> T: Deserialize<'de>,
    {
        let (sender, receiver) = sync_channel(1);
        let async_rpc_client = self.get_async_client()?;

        self.runtime.lock().unwrap().spawn(async move {
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
        let async_rpc_client = self.get_async_client()?;

        self.runtime.lock().unwrap().spawn(async move {
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

impl Drop for SyncRpcClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.runtime) == 1 {
            let sender = self.get_async_client().unwrap().websocket_writer;

            self.runtime.lock().unwrap().block_on(async move {
                let closemsg = CloseFrame {
                    code: CloseCode::Normal,
                    reason: std::borrow::Cow::Borrowed("close gracefully"),
                };
                let item = Message::Close(Some(closemsg));
                let _result = sender.lock().await.send(item).await;
            });
        }
    }
}
