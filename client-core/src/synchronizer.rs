//! global polling synchronizer
use std::collections::BTreeMap;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

use client_common::tendermint::Client;
use client_common::{SecKey, Storage};

use crate::wallet::syncer::{ObfuscationSyncerConfig, ProgressReport, WalletSyncer};
use crate::TransactionObfuscation;

type WalletName = String;
type WalletPassphrase = SecKey;

/// Synchronizer for transaction index which keeps polling for updates
#[derive(Default)]
pub struct PollingSynchronizer {
    wallets: Arc<Mutex<BTreeMap<WalletName, WalletPassphrase>>>,
    progress: Arc<Mutex<SynchronizerProgress>>,
}

impl PollingSynchronizer {
    /// Adds a wallet to polling synchronizer
    pub fn add_wallet(&self, wallet_name: String, wallet_seckey: SecKey) {
        let mut wallets = self.wallets.lock().unwrap();
        wallets.insert(wallet_name, wallet_seckey);
    }

    /// Removes wallet from polling synchronizer
    pub fn remove_wallet(&self, wallet_name: &str) {
        let mut wallets = self.wallets.lock().unwrap();
        wallets.remove(wallet_name);
    }
}

impl PollingSynchronizer {
    /// Spawns polling synchronizer in a thread
    pub fn spawn<S: Storage + 'static, C: Client + 'static, O: TransactionObfuscation + 'static>(
        &mut self,
        config: ObfuscationSyncerConfig<S, C, O>,
    ) {
        log::info!("Spawning polling synchronizer");
        let wallets = self.wallets.clone();
        let progress = self.progress.clone();

        let (sender, receiver) = channel();
        thread::spawn(move || loop {
            let wallets_to_synchronize = wallets
                .lock()
                .expect("Unable to acquire lock on wallets to synchronize in polling synchronizer")
                .clone();

            for (name, enckey) in wallets_to_synchronize.iter() {
                let result = WalletSyncer::with_obfuscation_config(
                    config.clone(),
                    Some(sender.clone()),
                    name.clone(),
                    enckey.clone(),
                )
                .and_then(|syncer| syncer.sync());
                if let Err(e) = result {
                    log::error!("Error while synchronizing wallet [{}]: {:?}", name, e);
                }
            }

            thread::sleep(time::Duration::from_millis(100));
        });

        thread::spawn(move || {
            for progress_report in receiver.iter() {
                match progress_report {
                    ProgressReport::Init {
                        finish_block_height,
                        ..
                    } => {
                        log::trace!(
                            "Polling synchronizer: Current block height: {}",
                            finish_block_height
                        );

                        let mut current_progress = progress
                            .lock()
                            .expect("Unable to acquire lock on polling synchronizer's progress");

                        (*current_progress).last_block_height = finish_block_height;
                    }
                    ProgressReport::Update {
                        wallet_name,
                        current_block_height,
                    } => {
                        log::trace!(
                            "Polling synchronizer: Synchronized block [{}] for wallet: {}",
                            current_block_height,
                            wallet_name
                        );

                        let mut current_progress = progress
                            .lock()
                            .expect("Unable to acquire lock on polling synchronizer's progress");

                        (*current_progress)
                            .synchronization_progress
                            .insert(wallet_name, current_block_height);
                    }
                }
            }
        });
    }
}

/// Struct for providing progress report of polling synchronizer
#[derive(Debug, Default, Clone)]
pub struct SynchronizerProgress {
    /// Last block height
    pub last_block_height: u64,
    /// Current sync progress of wallet
    pub synchronization_progress: BTreeMap<WalletName, u64>,
}
