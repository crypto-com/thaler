use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::{sink::SinkExt, stream::StreamExt};
use tokio::{
    sync::{oneshot::Sender, Mutex},
    task::JoinHandle,
    time::{delay_for, Duration},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use super::{
    async_rpc_client::{WebSocketReader, WebSocketWriter},
    types::{ConnectionState, JsonRpcResponse},
};

const MONITOR_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Creates a new websocket connection with given url
pub async fn new_connection(url: &str) -> Result<(WebSocketWriter, WebSocketReader)> {
    let (websocket_stream, _) = connect_async(url).await.with_context(|| {
        format!(
            "Unable to connect to tendermint websocket server at: {}",
            url
        )
    })?;

    Ok(websocket_stream.split())
}

/// Spawns websocket rpc loop in a new thread
///
/// # How it works
///
/// - Connects to websocket server at given `url` and splits the connection in `reader` and `writer`.
/// - Spawns a thread and runs `websocket_rpc_loop` in the thread which continues until the thread panics.
/// - For each websocket message received:
///   - Parse the message into JSON-RPC response.
///   - Pop the response channel from `channel_map` corresponding to response's `request_id`.
///   - Send the response to the channel.
pub fn spawn(
    channel_map: Arc<Mutex<HashMap<String, Sender<JsonRpcResponse>>>>,
    mut websocket_reader: WebSocketReader,
    websocket_writer: Arc<Mutex<WebSocketWriter>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(message) = websocket_reader.next().await {
            match message {
                Ok(message) => match message {
                    Message::Text(ref message) => handle_text(message, channel_map.clone()).await,
                    Message::Binary(ref message) => {
                        handle_slice(message, channel_map.clone()).await
                    }
                    Message::Ping(data) => send_pong(websocket_writer.clone(), data).await,
                    _ => {
                        log::trace!("Received unknown message: {:?}", message);
                    }
                },
                Err(err) => {
                    log::error!("Websocket error message: {}", err);
                    break;
                }
            }
        }
    })
}

/// Monitors websocket connection and retries if websocket is disconnected
///
/// # How it works
///
/// - Websocket connection has two possible states:
///   - `Connected`: `websocket_rpc_loop` is connected to websocket server
///   - `Disconnected`: `websocket_rpc_loop` is disconnected from websocket server. Connection should be retried.
/// - This function spawns a thread and runs connection state machine in a loop.
///   - If current state is `Disconnected`: Spawns `websocket_rpc_loop` and sets state to `Connected`.
///   - If current state is `Connected`: Waits for `websocket_rpc_loop` thread to end and sets state to `Disconnected`.
pub fn monitor(
    url: String,
    channel_map: Arc<Mutex<HashMap<String, Sender<JsonRpcResponse>>>>,
    loop_handle: JoinHandle<()>,
    websocket_writer: Arc<Mutex<WebSocketWriter>>,
) -> Arc<Mutex<ConnectionState>> {
    let connection_state = Arc::new(Mutex::new(ConnectionState::Connected));
    let connection_state_clone = connection_state.clone();

    tokio::spawn(async move {
        let mut connection_handle = Some(loop_handle);

        loop {
            let connection_state = *connection_state_clone.lock().await;

            let (new_connection_state, new_connection_handle) = match connection_state {
                ConnectionState::Disconnected => {
                    log::warn!("Websocket RPC is disconnected. Trying to reconnect");

                    match new_connection(&url).await {
                        Err(err) => {
                            log::warn!("Websocket RPC reconnection failure: {:?}", err);
                            (ConnectionState::Disconnected, None)
                        }
                        Ok((new_websocket_writer, new_websocket_reader)) => {
                            log::info!("Websocket RPC successfully reconnected");

                            *websocket_writer.lock().await = new_websocket_writer;

                            let new_handle = spawn(
                                channel_map.clone(),
                                new_websocket_reader,
                                websocket_writer.clone(),
                            );

                            (ConnectionState::Connected, Some(new_handle))
                        }
                    }
                }
                ConnectionState::Connected => {
                    let _ = connection_handle
                        .expect("Connection handle must be present when websocket is connected")
                        .await;
                    (ConnectionState::Disconnected, None)
                }
            };

            *connection_state_clone.lock().await = new_connection_state;
            connection_handle = new_connection_handle;

            delay_for(MONITOR_RETRY_INTERVAL).await;
        }
    });

    connection_state
}

/// Deserializes message from websocket into `JsonRpcResponse`
fn parse_text(message: &str) -> Result<JsonRpcResponse> {
    serde_json::from_str(&message)
        .with_context(|| format!("Unable to deserialize websocket message: {}", message))
}

/// Deserializes message from websocket into `JsonRpcResponse`
fn parse_slice(message: &[u8]) -> Result<JsonRpcResponse> {
    serde_json::from_slice(message)
        .with_context(|| format!("Unable to deserialize websocket message: {:?}", message))
}

/// Handles websocket text message
async fn handle_text(
    message: &str,
    channel_map: Arc<Mutex<HashMap<String, Sender<JsonRpcResponse>>>>,
) {
    log::trace!("Received text websocket message: {}", message);

    match parse_text(message) {
        Ok(text) => send_response(text, channel_map).await,
        Err(err) => log::error!("{:?}", err),
    }
}

/// Handles websocket binary message
async fn handle_slice(
    message: &[u8],
    channel_map: Arc<Mutex<HashMap<String, Sender<JsonRpcResponse>>>>,
) {
    log::trace!("Received binary websocket message: {:?}", message);
    match parse_slice(message) {
        Ok(slice) => send_response(slice, channel_map).await,
        Err(err) => log::error!("{:?}", err),
    }
}

/// Sends json response to appropriate channel
async fn send_response(
    response: JsonRpcResponse,
    channel_map: Arc<Mutex<HashMap<String, Sender<JsonRpcResponse>>>>,
) {
    let sender = channel_map.lock().await.remove(&response.id);

    if let Some(sender) = sender {
        log::debug!("Sending JSON-RPC response to channel");
        sender
            .send(response)
            .expect("Unable to send message on channel sender");
    } else {
        log::warn!("Received a websocket message with no configured handler");
    }
}

/// Silently sends pong message on websocket (does nothing in case of error)
async fn send_pong(websocket_writer: Arc<Mutex<WebSocketWriter>>, data: Vec<u8>) {
    let pong = websocket_writer
        .lock()
        .await
        .send(Message::Pong(data))
        .await;
    log::trace!("Received ping, sending pong: {:?}", pong);
}
