//! auto sync sharing state
//! shared between network and core threads
use std::sync::{Arc, Mutex};

use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use websocket::OwnedMessage;

/// give add wallet command via this queue
pub type AutoSyncQueue = std::sync::mpsc::Sender<OwnedMessage>;

/// Auto Sync Info for rpc query
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct AutoSyncInfo {
    /// normalized: 0.0 ~ 1.0
    pub progress: f64,
    /// current
    pub current_height: u64,
    /// max height
    pub max_height: u64,
    /// current syncing wallet name
    pub wallet: String,
    /// connected via websocket
    pub connected: bool,
    /// sync state : getting block, waiting, etc.
    pub state: String,
}

#[derive(Clone, Debug, Default)]
/// auto sync internal data
pub struct AutoSyncData {
    /// auto-sync info
    pub info: AutoSyncInfo,
    /// send queue
    pub send_queue: Option<std::sync::mpsc::Sender<OwnedMessage>>,
}

#[derive(Debug, Default, Clone)]
/// auto sync send queue arc
pub struct AutoSyncSendQueue {
    /// sending queue
    pub queue: Option<futures::sync::mpsc::Sender<OwnedMessage>>,
}

/// make new send queue
impl AutoSyncSendQueue {
    /// make new data
    pub fn new() -> Self {
        Default::default()
    }
}

/// auto sync send queue arc type
pub type AutoSyncSendQueueShared = Arc<Mutex<AutoSyncSendQueue>>;

/// auto sync data shared
pub type AutoSyncDataShared = Arc<Mutex<AutoSyncData>>;

#[derive(Clone, Debug)]
/// Wallet Information
pub struct WalletInfo {
    /// name of wallet
    pub name: String,
    /// passphrase of wallet
    pub passphrase: SecUtf8,
}
/// Wallet infos
pub type WalletInfos = std::collections::BTreeMap<String, WalletInfo>;

/// giving command via channel
#[derive(Serialize, Deserialize)]
pub struct AddWalletCommand {
    /// id of this command
    pub id: String,
    /// wallet name
    pub name: String,
    /// passphrase of wallet
    pub passphrase: SecUtf8,
}

/// Command to remove wallet from auto-sync
#[derive(Serialize, Deserialize)]
pub struct RemoveWalletCommand {
    /// ID of this command
    pub id: String,
    /// Wallet name
    pub name: String,
}

/// subscribe command
pub const CMD_SUBSCRIBE: &str = r#"
    {
        "jsonrpc": "2.0",
        "method": "subscribe",
        "id": "subscribe_reply",
        "params": {
            "query": "tm.event='NewBlock'"
        } 
    }"#;

/// block command
pub const CMD_BLOCK: &str = r#"
    {
        "method": "block",
        "jsonrpc": "2.0",
        "params": [ "2" ],
        "id": "block_reply"
    }"#;

/// status command
pub const CMD_STATUS: &str = r#"
    {
        "method": "status",
        "jsonrpc": "2.0",
        "params": [ ],
        "id": "status_reply"
    }"#;

/// giving command to auto-sync
pub type MyQueue = std::sync::mpsc::Sender<OwnedMessage>;
/// wait process interval
pub const WAIT_PROCESS_TIME: u128 = 5000; // milli seconds
/// block request interval
pub const BLOCK_REQUEST_TIME: u128 = 10; // milli seconds
/// receive polling interval
pub const RECEIVE_TIMEOUT: u64 = 10; //  milli seconds
