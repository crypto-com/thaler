use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

use crate::server::{to_rpc_error, WalletRequest};
use client_common::tendermint::Client;
use client_common::Storage;

use client_core::synchronizer::{AutoSync, AutoSyncInfo, ManualSynchronizer};
use client_core::BlockHandler;

#[rpc]
pub trait SyncRpc: Send + Sync {
    #[rpc(name = "sync")]
    fn sync(&self, request: WalletRequest) -> Result<()>;

    #[rpc(name = "sync_all")]
    fn sync_all(&self, request: WalletRequest) -> Result<()>;

    #[rpc(name = "sync_unlockWallet")]
    fn sync_unlock_wallet(&self, request: WalletRequest) -> Result<()>;

    #[rpc(name = "sync_info")]
    fn sync_info(&self) -> Result<AutoSyncInfo>;

    #[rpc(name = "sync_stop")]
    fn sync_stop(&self, request: WalletRequest) -> Result<()>;
}

pub struct SyncRpcImpl<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    synchronizer: ManualSynchronizer<S, C, H>,
    auto_synchronizer: AutoSync,
}

impl<S, C, H> SyncRpc for SyncRpcImpl<S, C, H>
where
    S: Storage + 'static,
    C: Client + 'static,
    H: BlockHandler + 'static,
{
    #[inline]
    fn sync(&self, request: WalletRequest) -> Result<()> {
        self.synchronizer
            .sync(&request.name, &request.passphrase, None, None)
            .map_err(to_rpc_error)
    }

    #[inline]
    fn sync_all(&self, request: WalletRequest) -> Result<()> {
        self.synchronizer
            .sync_all(&request.name, &request.passphrase, None, None)
            .map_err(to_rpc_error)
    }

    #[inline]
    fn sync_unlock_wallet(&self, request: WalletRequest) -> Result<()> {
        self.auto_synchronizer
            .add_wallet(request.name, request.passphrase)
            .map_err(to_rpc_error)
    }

    #[inline]
    fn sync_info(&self) -> Result<AutoSyncInfo> {
        self.auto_synchronizer.sync_info().map_err(to_rpc_error)
    }

    #[inline]
    fn sync_stop(&self, request: WalletRequest) -> Result<()> {
        self.auto_synchronizer
            .remove_wallet(request.name)
            .map_err(to_rpc_error)
    }
}

impl<S, C, H> SyncRpcImpl<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    #[inline]
    pub fn new(synchronizer: ManualSynchronizer<S, C, H>, auto_synchronizer: AutoSync) -> Self {
        SyncRpcImpl {
            synchronizer,
            auto_synchronizer,
        }
    }
}
