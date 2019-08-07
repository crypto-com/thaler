use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

use chain_core::state::account::StakedStateAddress;
use client_common::{Error, ErrorKind, PrivateKey, PublicKey, Storage};
use client_common::tendermint::Client;
use client_core::{MultiSigWalletClient, WalletClient};
use client_index::synchronizer::ManualSynchronizer;
use client_index::BlockHandler;

use crate::server::{to_rpc_error, WalletRequest};

#[rpc]
pub trait SyncRpc: Send + Sync {
    #[rpc(name = "sync")]
    fn sync(&self, request: WalletRequest) -> Result<()>;

    #[rpc(name = "sync_all")]
    fn sync_all(&self, request: WalletRequest) -> Result<()>;
}

pub struct SyncRpcImpl<T, S, C, H>
where
    T: WalletClient,
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    client: T,
    synchronizer: ManualSynchronizer<S, C, H>,
}

impl<T, S, C, H> SyncRpc for SyncRpcImpl<T, S, C, H>
where
    T: WalletClient + MultiSigWalletClient + 'static,
    S: Storage + 'static,
    C: Client + 'static,
    H: BlockHandler + 'static,
{
    fn sync(&self, request: WalletRequest) -> Result<()> {
        let (view_key, private_key, staking_addresses) = self.prepare_synchronized_parameters(&request)?;

        self.synchronizer
            .sync(&staking_addresses, &view_key, &private_key)
            .map_err(to_rpc_error)
    }

    fn sync_all(&self, request: WalletRequest) -> Result<()> {
        let (view_key, private_key, staking_addresses) = self.prepare_synchronized_parameters(&request)?;

        self.synchronizer
            .sync_all(&staking_addresses, &view_key, &private_key)
            .map_err(to_rpc_error)
    }
}

impl<T, S, C, H> SyncRpcImpl<T, S, C, H>
where
    T: WalletClient,
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    pub fn new(
        client: T,
        synchronizer: ManualSynchronizer<S, C, H>,
    ) -> Self {
        SyncRpcImpl {
            client,
            synchronizer,
        }
    }

    fn prepare_synchronized_parameters(&self, request: &WalletRequest) -> Result<(PublicKey, PrivateKey, Vec<StakedStateAddress>)> {
        let view_key = self
            .client
            .view_key(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;
        let private_key = self
            .client
            .private_key(&request.passphrase, &view_key)
            .map_err(to_rpc_error)?
            .ok_or_else(|| Error::from(ErrorKind::WalletNotFound))
            .map_err(to_rpc_error)?;

        let staking_addresses = self
            .client
            .staking_addresses(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;

        Ok((view_key, private_key, staking_addresses))
    }
}
