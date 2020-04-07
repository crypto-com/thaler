#![cfg(feature = "websocket-rpc")]
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Websocket connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Websocket is connected
    Connected,
    /// Websocket is disconnected
    Disconnected,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest<'a, 'b> {
    pub id: &'a str,
    pub jsonrpc: &'static str,
    pub method: &'a str,
    pub params: &'b [Value],
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcResponse {
    pub id: String,
    pub jsonrpc: String,
    pub error: Option<JsonRpcError>,
    pub result: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

impl std::error::Error for JsonRpcError {}

impl fmt::Display for JsonRpcError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RPC error response: {:?}", self)
    }
}
