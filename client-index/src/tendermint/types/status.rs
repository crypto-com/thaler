#![allow(missing_docs)]

use failure::ResultExt;
use serde::{Deserialize, Serialize};

use client_common::{ErrorKind, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    node_info: NodeInfo,
    sync_info: SyncInfo,
    validator_info: ValidatorInfo,
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeInfo {
    protocol_version: ProtocolVersion,
    id: String,
    listen_addr: String,
    network: String,
    version: String,
    channels: String,
    moniker: String,
    other: Other,
}

#[derive(Debug, Serialize, Deserialize)]
struct Other {
    tx_index: String,
    rpc_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProtocolVersion {
    p2p: String,
    block: String,
    app: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncInfo {
    latest_block_hash: String,
    latest_app_hash: String,
    latest_block_height: String,
    latest_block_time: String,
    catching_up: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidatorInfo {
    address: String,
    pub_key: PubKey,
    voting_power: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PubKey {
    #[serde(rename = "type")]
    pub_key_type: String,
    value: String,
}

impl Status {
    /// Returns last block height
    pub fn last_block_height(&self) -> Result<u64> {
        Ok(self
            .sync_info
            .latest_block_height
            .parse::<u64>()
            .context(ErrorKind::DeserializationError)?)
    }
}
