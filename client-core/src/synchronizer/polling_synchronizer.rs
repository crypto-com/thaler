use std::collections::BTreeMap;
use std::mem;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

use secstr::SecUtf8;

use client_common::tendermint::Client;
use client_common::Storage;

use crate::synchronizer::{ManualSynchronizer, ProgressReport};
use crate::BlockHandler;

type WalletName = String;
type WalletPassphrase = SecUtf8;

/// Synchronizer for transaction index which keeps polling for updates
pub struct PollingSynchronizer<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    manual_synchronizer: Option<ManualSynchronizer<S, C, H>>,
    wallets: Arc<Mutex<BTreeMap<WalletName, WalletPassphrase>>>,
    progress: Arc<Mutex<SynchronizerProgress>>,
}

impl<S, C, H> PollingSynchronizer<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    /// Adds a wallet to polling synchronizer
    pub fn add_wallet(&self, wallet_name: String, wallet_passphrase: SecUtf8) {
        let mut wallets = self.wallets.lock().unwrap();
        wallets.insert(wallet_name, wallet_passphrase);
    }

    /// Removes wallet from polling synchronizer
    pub fn remove_wallet(&self, wallet_name: &str) {
        let mut wallets = self.wallets.lock().unwrap();
        wallets.remove(wallet_name);
    }
}

impl<S, C, H> PollingSynchronizer<S, C, H>
where
    S: Storage + 'static,
    C: Client + 'static,
    H: BlockHandler + 'static,
{
    /// Spawns polling synchronizer in a thread
    pub fn spawn(&mut self) {
        if self.manual_synchronizer.is_some() {
            log::info!("Spawning polling synchronizer");

            let manual_synchronizer = mem::replace(&mut self.manual_synchronizer, None).unwrap();
            let wallets = self.wallets.clone();
            let progress = self.progress.clone();

            let (sender, receiver) = channel();

            thread::spawn(move || loop {
                let wallets_to_synchronize = wallets
                    .lock()
                    .expect(
                        "Unable to acquire lock on wallets to synchronize in polling synchronizer",
                    )
                    .clone();

                for (name, passphrase) in wallets_to_synchronize.iter() {
                    if let Err(e) =
                        manual_synchronizer.sync(name, passphrase, None, Some(sender.clone()))
                    {
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

                            let mut current_progress = progress.lock().expect(
                                "Unable to acquire lock on polling synchronizer's progress",
                            );

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

                            let mut current_progress = progress.lock().expect(
                                "Unable to acquire lock on polling synchronizer's progress",
                            );

                            (*current_progress)
                                .synchronization_progress
                                .insert(wallet_name, current_block_height);
                        }
                    }
                }
            });
        } else {
            log::error!("Polling synchronizer already running");
        }
    }
}

impl<S, C, H> From<ManualSynchronizer<S, C, H>> for PollingSynchronizer<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    fn from(manual_synchronizer: ManualSynchronizer<S, C, H>) -> Self {
        Self {
            manual_synchronizer: Some(manual_synchronizer),
            wallets: Default::default(),
            progress: Default::default(),
        }
    }
}

/// Struct for providing progress report of polling synchronizer
#[derive(Debug, Default, Clone)]
pub struct SynchronizerProgress {
    pub last_block_height: u64,
    pub synchronization_progress: BTreeMap<WalletName, u64>,
}
