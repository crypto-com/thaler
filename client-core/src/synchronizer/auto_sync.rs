//!
//! automatic sync
//!
//! how to use
//! 1. create auto-sync & run
//! let autosync: AutoSync::new();
//! autosync.run(url, tendermint_client, storage.clone(), block_handler);
//!
//! 2. unlock wallet
//! autosync.add_wallet(request.name, view_key, private_key, staking_addresses);
//!
use std::thread;

use secstr::SecUtf8;
use serde_json::json;
use websocket::OwnedMessage;

use client_common::tendermint::Client;
use client_common::Result;
use client_common::Storage;

use super::auto_sync_data::{
    AddWalletCommand, AutoSyncDataShared, AutoSyncInfo, RemoveWalletCommand,
};
use super::auto_synchronizer::AutoSynchronizer;
use crate::BlockHandler;

#[derive(Clone, Debug, Default)]
/// facade for auto sync manager
pub struct AutoSync {
    data: AutoSyncDataShared,
}

impl AutoSync {
    /// create auto sync
    pub fn new() -> Self {
        Default::default()
    }
    /// activate auto sync
    pub fn run<S: Storage + Clone + 'static, C: Client + 'static, H: BlockHandler + 'static>(
        &mut self,
        url: String,
        client: C,
        storage: S,
        block_handler: H,
    ) {
        let mut web = AutoSynchronizer::new(url, self.data.clone());
        web.run(client, storage, block_handler, self.data.clone());
        let websocket_queue = web.get_send_queue();

        thread::spawn(move || {
            // some work here
            log::info!("start websocket");
            let _ = web.run_network();
        });

        // set send queue
        {
            let mut data = self.data.lock().expect("auto sync lock");
            data.send_queue = websocket_queue;
        }
    }

    /// add wallet
    /// PublicKey, PrivateKey, Vec<StakedStateAddress>
    pub fn add_wallet(&self, name: String, passphrase: SecUtf8) -> Result<()> {
        let data = json!(AddWalletCommand {
            id: "add_wallet".to_string(),
            name,
            passphrase
        });

        self.send_json(data)
    }

    /// Get sync information
    pub fn sync_info(&self) -> AutoSyncInfo {
        let mut ret = AutoSyncInfo::default();

        {
            let data = self.data.lock().expect("get progress autosync lock");
            ret.current_height = data.current_height;
            ret.max_height = data.max_height;
            ret.wallet = data.wallet.clone();
            ret.connected = data.connected;
            ret.state = data.state.clone();
        }
        ret
    }

    /// Removes a wallet from auto-sync
    pub fn remove_wallet(&self, name: String) -> Result<()> {
        let data = json!(RemoveWalletCommand {
            id: "remove_wallet".to_string(),
            name
        });

        self.send_json(data)
    }

    /// send json
    pub fn send_json(&self, json: serde_json::Value) -> Result<()> {
        let send_queue: Option<std::sync::mpsc::Sender<OwnedMessage>>;
        {
            let data = self.data.lock().expect("auto sync lock");
            send_queue = data.send_queue.clone();
        }
        let tmp_queue = send_queue.expect("auto sync send queue");
        AutoSynchronizer::send_json(&tmp_queue, json);
        Ok(())
    }

    /// get progress , return information as tuple
    /// (progress:0.0~1.0, current_wallet_name)
    pub fn get_progress(&self) -> (f64, String) {
        let data = self.data.lock().expect("get progress autosync lock");
        (data.progress, data.wallet.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_sync_flow() {
        let sync = AutoSync::new();
        let initial_state = sync.get_progress();
        assert!(initial_state.0 == 0.0);
        assert!(initial_state.1 == "");
    }
}
