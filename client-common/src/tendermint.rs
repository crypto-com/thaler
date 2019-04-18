//! Tendermint client operations
mod client;
#[cfg(feature = "rpc")]
mod rpc_client;

pub mod types;

pub use client::Client;
#[cfg(feature = "rpc")]
pub use rpc_client::RpcClient;
