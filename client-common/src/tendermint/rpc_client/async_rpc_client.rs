use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream},
};
use serde::Deserialize;
use serde_json::Value;
use tokio::{
    net::TcpStream,
    sync::{
        oneshot::{channel, Receiver, Sender},
        Mutex,
    },
    time::{delay_for, timeout, Duration},
};
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

/// websocket writer
pub type WebSocketWriter = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
/// websocket reader
pub type WebSocketReader = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;
use super::{
    types::{ConnectionState, JsonRpcRequest, JsonRpcResponse},
    websocket_rpc_loop,
};

const WAIT_FOR_CONNECTION_SLEEP_INTERVAL: Duration = Duration::from_millis(200);
const WAIT_FOR_CONNECTION_COUNT: usize = 50;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Tendermint RPC Client (uses websocket in transport layer)
#[derive(Clone)]
pub struct AsyncRpcClient {
    connection_state: Arc<Mutex<ConnectionState>>,
    /// websocket
    pub websocket_writer: Arc<Mutex<WebSocketWriter>>,
    channel_map: Arc<Mutex<HashMap<String, Sender<JsonRpcResponse>>>>,
    unique_id: Arc<AtomicUsize>,
}

impl AsyncRpcClient {
    /// Creates a new instance of `AsyncRpcClient`
    //
    // # How it works
    //
    // - Spawns `websocket_rpc_loop`.
    // - Spawns `websocket_rpc_loop` monitor.
    pub async fn new(url: &str) -> Result<Self> {
        let channel_map: Arc<Mutex<HashMap<String, Sender<JsonRpcResponse>>>> = Default::default();

        let (websocket_writer, websocket_reader) = websocket_rpc_loop::new_connection(url).await?;
        let websocket_writer = Arc::new(Mutex::new(websocket_writer));

        let loop_handle = websocket_rpc_loop::spawn(
            channel_map.clone(),
            websocket_reader,
            websocket_writer.clone(),
        );

        let connection_state = websocket_rpc_loop::monitor(
            url.to_owned(),
            channel_map.clone(),
            loop_handle,
            websocket_writer.clone(),
        );

        Ok(Self {
            connection_state,
            websocket_writer,
            channel_map,
            unique_id: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Sends a RPC request
    //
    // # How it works
    //
    // - Prepares JSON-RPC request from `method` and `params` (generates a random `request_id`).
    // - Creates a `sync_channel` pair
    // - Inserts `channel_sender` to `channel_map` corresponding to generated `request_id`.
    // - Ensure that the `websocket_rpc_loop` is in `Connected` state.
    // - Send request websocket message.
    // - Receive response on `channel_receiver`.
    pub async fn request(&self, method: &str, params: &[Value]) -> Result<Value> {
        let (id, channel_receiver) = self.send_request(method, params).await?;
        self.receive_response(method, params, &id, channel_receiver)
            .await
    }

    /// Sends RPC requests for a batch.
    ///
    /// # Note
    ///
    /// This does not use batch JSON-RPC requests but makes multiple single JSON-RPC requests in parallel.
    ///
    /// TODO: Usage of `Vec` can be removed once we execute it in a purely async context
    pub async fn request_batch(&self, batch_params: &[(&str, Vec<Value>)]) -> Result<Vec<Value>> {
        if batch_params.is_empty() {
            // Do not send empty batch requests
            return Ok(Default::default());
        }

        let mut receivers = Vec::with_capacity(batch_params.len());

        for (ref method, ref params) in batch_params.iter() {
            let (id, channel_receiver) = self.send_request(method, params).await?;
            receivers.push((id, channel_receiver));
        }

        let mut responses = Vec::with_capacity(batch_params.len());

        for (i, (id, receiver)) in receivers.into_iter().enumerate() {
            let method = batch_params[i].0;
            let params = &batch_params[i].1;

            let response = self.receive_response(method, params, &id, receiver).await?;
            responses.push(response);
        }

        Ok(responses)
    }

    /// Makes an RPC call and deserializes the response
    pub async fn call<T>(&self, method: &str, params: &[Value]) -> Result<T>
    where
        for<'de> T: Deserialize<'de>,
    {
        let response_value = self.request(method, params).await?;
        serde_json::from_value(response_value).with_context(|| {
            format!(
                "Unable to deserialize `{}` from JSON-RPC response for params: {:?}",
                method, params
            )
        })
    }

    /// Makes RPC call in batch and deserializes responses
    ///
    /// TODO: Usage of `Vec` can be removed once we execute it in a purely async context
    pub async fn call_batch<T>(&self, batch_params: &[(&str, Vec<Value>)]) -> Result<Vec<T>>
    where
        for<'de> T: Deserialize<'de>,
    {
        let response_values = self.request_batch(batch_params).await?;
        let mut responses = Vec::with_capacity(response_values.len());

        for (i, response_value) in response_values.into_iter().enumerate() {
            let method = batch_params[i].0;
            let params = &batch_params[i].1;

            let response = serde_json::from_value(response_value).with_context(|| {
                format!(
                    "Unable to deserialize `{}` from JSON-RPC response for params: {:?}",
                    method, params
                )
            })?;

            responses.push(response);
        }

        Ok(responses)
    }

    /// Sends a JSON-RPC request and returns `request_id` and `response_channel`
    async fn send_request(
        &self,
        method: &str,
        params: &[Value],
    ) -> Result<(String, Receiver<JsonRpcResponse>)> {
        let id = self.unique_id.fetch_add(1, Ordering::Relaxed).to_string();
        let message = prepare_message(&id, method, params)?;
        let (channel_sender, channel_receiver) = channel::<JsonRpcResponse>();

        self.channel_map
            .lock()
            .await
            .insert(id.clone(), channel_sender);

        self.ensure_connected().await?;

        if let Err(err) = self
            .websocket_writer
            .lock()
            .await
            .send(message)
            .await
            .context("Unable to send message to websocket writer")
        {
            self.channel_map.lock().await.remove(&id);
            bail!(err);
        }

        Ok((id, channel_receiver))
    }

    /// Receives response from websocket for given id.
    async fn receive_response(
        &self,
        method: &str,
        params: &[Value],
        id: &str,
        receiver: Receiver<JsonRpcResponse>,
    ) -> Result<Value> {
        let response = timeout(RESPONSE_TIMEOUT, receiver)
            .await
            .context("Tendermint RPC request timed out")?;

        let response = match response.context("Unable to receive message from channel receiver") {
            Ok(response) => response,
            Err(err) => {
                self.channel_map.lock().await.remove(id);
                bail!(err)
            }
        };

        match response.error {
            Some(err) => bail!(
                "Error response from tendermint RPC for request method ({}) and params ({:?}): {}",
                method,
                params,
                err
            ),
            None => Ok(response.result.unwrap_or_default()),
        }
    }

    /// Ensures that the websocket is connected.
    async fn ensure_connected(&self) -> Result<()> {
        for _ in 0..WAIT_FOR_CONNECTION_COUNT {
            if ConnectionState::Connected == *self.connection_state.lock().await {
                return Ok(());
            }

            delay_for(WAIT_FOR_CONNECTION_SLEEP_INTERVAL).await;
        }

        Err(anyhow!("Websocket connection disconnected"))
    }
}

fn prepare_message(id: &str, method: &str, params: &[Value]) -> Result<Message> {
    let request = JsonRpcRequest {
        id,
        jsonrpc: "2.0",
        method,
        params,
    };

    let request_json =
        serde_json::to_string(&request).context("Unable to serialize RPC request to JSON")?;
    let message = Message::Text(request_json);

    Ok(message)
}
