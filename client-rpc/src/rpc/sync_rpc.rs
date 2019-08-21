use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

use crate::rpc::websocket_rpc::AddWalletCommand;
use crate::server::{to_rpc_error, WalletRequest};
use chain_core::state::account::StakedStateAddress;
use client_common::tendermint::Client;
use client_common::{Error, ErrorKind, PrivateKey, PublicKey, Storage};
use client_core::{MultiSigWalletClient, WalletClient};
use client_index::synchronizer::ManualSynchronizer;
use client_index::BlockHandler;
use serde_json::json;
use std::sync::Mutex;
use websocket::OwnedMessage;
#[rpc]
pub trait SyncRpc: Send + Sync {
    #[rpc(name = "sync")]
    fn sync(&self, request: WalletRequest) -> Result<()>;

    #[rpc(name = "sync_all")]
    fn sync_all(&self, request: WalletRequest) -> Result<()>;

    #[rpc(name = "sync_continuous")]
    fn sync_continuous(&self, request: WalletRequest) -> Result<String>;
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
    websocket_queue: Mutex<Option<std::sync::mpsc::Sender<OwnedMessage>>>,
}

impl<T, S, C, H> SyncRpc for SyncRpcImpl<T, S, C, H>
where
    T: WalletClient + MultiSigWalletClient + 'static,
    S: Storage + 'static,
    C: Client + 'static,
    H: BlockHandler + 'static,
{
    fn sync(&self, request: WalletRequest) -> Result<()> {
        let (view_key, private_key, staking_addresses) =
            self.prepare_synchronized_parameters(&request)?;

        self.synchronizer
            .sync(&staking_addresses, &view_key, &private_key)
            .map_err(to_rpc_error)
    }

    fn sync_all(&self, request: WalletRequest) -> Result<()> {
        let (view_key, private_key, staking_addresses) =
            self.prepare_synchronized_parameters(&request)?;

        self.synchronizer
            .sync_all(&staking_addresses, &view_key, &private_key)
            .map_err(to_rpc_error)
    }

    fn sync_continuous(&self, request: WalletRequest) -> Result<String> {
        match self.prepare_synchronized_parameters(&request) {
            Ok(_) => {}
            Err(_) => return Ok("incorrect password".to_string()),
        }

        let data = json!(AddWalletCommand {
            id: "add_wallet".to_string(),
            wallet: request.clone(),
        });
        let ret = "OK".to_string();
        {
            let sendqoption = self.websocket_queue.lock().unwrap();
            assert!(sendqoption.is_some());
            let sendq = sendqoption.as_ref().unwrap();
            sendq
                .send(OwnedMessage::Text(serde_json::to_string(&data).unwrap()))
                .unwrap();
        }
        Ok(ret)
    }
}

impl<T, S, C, H> SyncRpcImpl<T, S, C, H>
where
    T: WalletClient,
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    pub fn new(client: T, synchronizer: ManualSynchronizer<S, C, H>) -> Self {
        SyncRpcImpl {
            client,
            synchronizer,
            websocket_queue: Mutex::new(None),
        }
    }

    pub fn set_websocket_queue(&mut self, q: std::sync::mpsc::Sender<OwnedMessage>) {
        *self.websocket_queue.lock().unwrap() = Some(q);
    }

    fn prepare_synchronized_parameters(
        &self,
        request: &WalletRequest,
    ) -> Result<(PublicKey, PrivateKey, Vec<StakedStateAddress>)> {
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
