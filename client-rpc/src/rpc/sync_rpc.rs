use super::sync_worker::SyncWorker;
use super::sync_worker::WorkerShared;
use crate::server::to_rpc_error;
use client_common::tendermint::Client;
use client_common::Storage;
use client_core::wallet::syncer::AddressRecovery;
use client_core::wallet::syncer::ProgressReport;
use client_core::wallet::syncer::{ObfuscationSyncerConfig, WalletSyncer};
use client_core::wallet::WalletRequest;
use client_core::TransactionObfuscation;
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
// seconds
const NOTIFICATION_TIME: u64 = 2;
pub trait CBindingCallback: Send + Sync {
    fn progress(&mut self, current: u64, start: u64, end: u64) -> i32;
    fn set_user(&mut self, user: u64);
    fn get_user(&self) -> u64;
}

#[derive(Clone)]
pub struct CBindingCore {
    pub data: Arc<Mutex<dyn CBindingCallback>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RunSyncResult {
    name: String,
    message: String,
    progress: RunSyncProgressResult,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RunSyncProgressResult {
    pub name: String,
    pub message: String,
    pub percent: f32,
    pub current: u64,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SyncRequest {
    blocking: bool,
    reset: bool,
    do_loop: bool,
}

impl Default for SyncRequest {
    fn default() -> Self {
        Self {
            blocking: true,
            reset: false,
            do_loop: false,
        }
    }
}

#[rpc(server)]
pub trait SyncRpc: Send + Sync {
    #[rpc(name = "sync")]
    fn sync(&self, request: WalletRequest, sync_reqeust: SyncRequest) -> Result<RunSyncResult>;

    #[rpc(name = "sync_progress")]
    fn sync_progress(&self, request: WalletRequest) -> Result<RunSyncProgressResult>;

    #[rpc(name = "sync_stop")]
    fn sync_stop(&self, request: WalletRequest) -> Result<()>;
}

pub struct SyncRpcImpl<S, C, O, T>
where
    S: Storage,
    C: Client,
    O: TransactionObfuscation,
    T: AddressRecovery,
{
    config: ObfuscationSyncerConfig<S, C, O>,

    progress_callback: Option<CBindingCore>,
    worker: WorkerShared,
    recover_address: T,
}

impl<S, C, O, T> SyncRpcImpl<S, C, O, T>
where
    S: Storage + 'static,
    C: Client + 'static,
    O: TransactionObfuscation + 'static,
    T: AddressRecovery + 'static,
{
    pub fn new(
        config: ObfuscationSyncerConfig<S, C, O>,
        progress_callback: Option<CBindingCore>,

        recover_address: T,
    ) -> Self {
        SyncRpcImpl {
            config,

            progress_callback,
            worker: Arc::new(Mutex::new(SyncWorker::new())),

            recover_address,
        }
    }
}

fn process_sync<S, C, O, T>(
    config: ObfuscationSyncerConfig<S, C, O>,
    request: WalletRequest,
    reset: bool,
    progress_callback: Option<CBindingCore>,
    recover_address: T,
) -> Result<()>
where
    S: Storage,
    C: Client,
    O: TransactionObfuscation,
    T: AddressRecovery,
{
    let mut syncer = WalletSyncer::with_obfuscation_config(
        config,
        request.name,
        request.enckey,
        recover_address,
    )
    .map_err(to_rpc_error)?;
    if reset {
        syncer.reset_state().map_err(to_rpc_error)?;
    }

    if progress_callback.is_none() {
        return syncer.sync(|_| true).map_err(to_rpc_error);
    }

    let mut init_block_height = 0;
    let mut final_block_height = 0;
    syncer
        .sync(|report: ProgressReport| -> bool {
            match report {
                ProgressReport::Init {
                    start_block_height,
                    finish_block_height,
                    ..
                } => {
                    init_block_height = start_block_height;
                    final_block_height = finish_block_height;
                    if let Some(delegator) = &progress_callback {
                        {
                            let mut user_callback =
                                delegator.data.lock().expect("get cbinding callback");
                            user_callback.progress(0, init_block_height, final_block_height);
                            return true;
                        }
                    }
                    true
                }
                ProgressReport::Update {
                    current_block_height,
                    ..
                } => {
                    if let Some(delegator) = &progress_callback {
                        {
                            let mut user_callback =
                                delegator.data.lock().expect("get cbinding callback");
                            return 1
                                == user_callback.progress(
                                    current_block_height,
                                    init_block_height,
                                    final_block_height,
                                );
                        }
                    }
                    true
                }
            }
        })
        .map_err(to_rpc_error)
}

impl<S, C, O, T> SyncRpcImpl<S, C, O, T>
where
    S: Storage + 'static,
    C: Client + 'static,
    O: TransactionObfuscation + 'static,
    T: AddressRecovery + 'static,
{
    fn do_run_sync(
        &self,
        request: WalletRequest,
        reset: bool,
        do_loop: bool,
    ) -> Result<RunSyncResult> {
        log::info!("run_sync");
        let config = self.config.clone();
        let recover_address = self.recover_address.clone();

        let name = request.name.clone();
        let worker = self.worker.clone();
        let userrequest = request.clone();

        let progress = worker
            .lock()
            .expect("get sync worker lock")
            .get_progress(&name);
        if let Ok(value) = progress {
            return Ok(RunSyncResult {
                message: "already syncing wallet".to_string(),
                name: request.name,
                progress: value,
            });
        }

        thread::spawn(move || {
            let localworker = worker;
            localworker.lock().expect("get sync worker lock").add(&name);
            let node = localworker.lock().expect("get sync worker lock").get(&name);
            let syncnode = node.expect("get progress callback");
            let usercallback = Some(CBindingCore { data: syncnode });
            loop {
                let result = process_sync(
                    config.clone(),
                    userrequest.clone(),
                    reset,
                    usercallback.clone(),
                    recover_address.clone(),
                );
                log::info!("process_sync finished {} {:?}", name, result);
                if result.is_err() {
                    break;
                }

                if localworker
                    .lock()
                    .expect("get sync worker lock")
                    .get_stop(&name)
                {
                    break;
                }

                localworker
                    .lock()
                    .expect("get sync worker lock")
                    .set_complete(&name);

                // notify
                log::info!("wait for notification {}", name);
                std::thread::sleep(std::time::Duration::from_secs(NOTIFICATION_TIME));

                if !do_loop {
                    break;
                }
            }
            localworker
                .lock()
                .expect("get sync worker lock")
                .remove(&name);
            log::info!("sync thread finished {}", name);
        });

        Ok(RunSyncResult {
            message: "started sync wallet".to_string(),
            name: request.name,
            progress: RunSyncProgressResult::default(),
        })
    }
}

impl<S, C, O, T> SyncRpc for SyncRpcImpl<S, C, O, T>
where
    S: Storage + 'static,
    C: Client + 'static,
    O: TransactionObfuscation + 'static,
    T: AddressRecovery + 'static,
{
    #[inline]
    fn sync(&self, request: WalletRequest, sync_request: SyncRequest) -> Result<RunSyncResult> {
        log::info!("sync {:?}", sync_request);
        if sync_request.blocking {
            process_sync(
                self.config.clone(),
                request,
                sync_request.reset,
                self.progress_callback.clone(),
                self.recover_address.clone(),
            )?;
            Ok(RunSyncResult::default())
        } else {
            self.do_run_sync(request, sync_request.reset, sync_request.do_loop)
        }
    }

    #[inline]
    fn sync_progress(&self, request: WalletRequest) -> Result<RunSyncProgressResult> {
        self.worker
            .lock()
            .expect("get sync worker lock")
            .get_progress(&request.name)
    }

    #[inline]
    fn sync_stop(&self, request: WalletRequest) -> Result<()> {
        self.worker
            .lock()
            .expect("get sync worker lock")
            .stop(&request.name)
    }
}

impl<S, C, O, T> Drop for SyncRpcImpl<S, C, O, T>
where
    S: Storage,
    C: Client,
    O: TransactionObfuscation,
    T: AddressRecovery,
{
    fn drop(&mut self) {}
}
