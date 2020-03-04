//! global polling synchronizer
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
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
    should_run: Arc<AtomicBool>,
    sync_thread: Option<thread::JoinHandle<()>>,
    progress_thread: Option<thread::JoinHandle<()>>,
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

        self.should_run.store(true, Ordering::Relaxed);
        let should_run = self.should_run.clone();

        let (sender, receiver) = channel();
        let progress_callback = move |report| {
            println!("{:?}", report);
            sender.send(report).unwrap();
            true
        };
        self.sync_thread = Some(thread::spawn(move || {
            while should_run.load(Ordering::Relaxed) {
                let wallets_to_synchronize = wallets
                    .lock()
                    .expect(
                        "Unable to acquire lock on wallets to synchronize in polling synchronizer",
                    )
                    .clone();

                for (name, enckey) in wallets_to_synchronize.iter() {
                    let result = WalletSyncer::with_obfuscation_config(
                        config.clone(),
                        name.clone(),
                        enckey.clone(),
                    )
                    .and_then(|syncer| syncer.sync(progress_callback.clone()));
                    if let Err(e) = result {
                        log::error!("Error while synchronizing wallet [{}]: {:?}", name, e);
                    }
                }

                thread::sleep(time::Duration::from_millis(100));
            }
        }));

        self.progress_thread = Some(thread::spawn(move || {
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
        }));
    }

    /// Stop the auto synchronizer thread
    pub fn stop(&mut self) {
        self.should_run.store(false, Ordering::Relaxed);
        if let Some(thread) = self.sync_thread.take() {
            thread.join().expect("join auto syncer thread failed");
        }
        if let Some(thread) = self.progress_thread.take() {
            thread.join().expect("join progress report thread failed");
        }
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
