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

use crate::auto_sync_data::{AddWalletCommand, AutoSyncData, AutoSyncDataShared};
use crate::auto_synchronizer::AutoSynchronizer;
use crate::BlockHandler;
use chain_core::state::account::StakedStateAddress;
use client_common::tendermint::Client;
use client_common::Storage;
use client_common::{PrivateKey, PublicKey};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::thread;
use websocket::OwnedMessage;
#[derive(Clone, Debug)]
/// facade for auto sync manager
pub struct AutoSync {
    data: AutoSyncDataShared,
}

impl Default for AutoSync {
    fn default() -> Self {
        AutoSync {
            data: Arc::new(Mutex::new(AutoSyncData::new())),
        }
    }
}
impl AutoSync {
    /// create auto sync
    pub fn new() -> Self {
        Default::default()
    }
    /// activate auto sync
    pub fn run<S: Storage + 'static, C: Client + 'static, H: BlockHandler + 'static>(
        &mut self,
        url: String,
        client: C,
        storage: S,
        block_handler: H,
    ) {
        let mut web = AutoSynchronizer::new(url);
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
    pub fn add_wallet(
        &self,
        name: String,
        view_key: PublicKey,
        private_key: PrivateKey,
        staking_addresses: Vec<StakedStateAddress>,
    ) {
        let data = json!(AddWalletCommand {
            id: "add_wallet".to_string(),
            name,
            staking_addresses,
            view_key,
            private_key: private_key.serialize(),
        });

        self.send_json(data);
    }
    /// send json
    pub fn send_json(&self, json: serde_json::Value) {
        {
            let send_queue: Option<std::sync::mpsc::Sender<OwnedMessage>>;
            {
                let data = self.data.lock().expect("auto sync lock");
                send_queue = data.send_queue.clone();
            }
            let tmp_queue = send_queue.expect("auto sync send queue");
            AutoSynchronizer::send_json(&tmp_queue, json);
        }
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
