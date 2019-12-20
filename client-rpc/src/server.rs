use crate::program::Options;
use crate::rpc::multisig_rpc::{MultiSigRpc, MultiSigRpcImpl};
use crate::rpc::staking_rpc::{StakingRpc, StakingRpcImpl};
use crate::rpc::sync_rpc::{SyncRpc, SyncRpcImpl};
use crate::rpc::transaction_rpc::{TransactionRpc, TransactionRpcImpl};
use crate::rpc::wallet_rpc::{WalletRpc, WalletRpcImpl};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use chain_core::init::network::{get_network, get_network_id, init_chain_id};
use chain_core::tx::fee::LinearFee;
use client_common::storage::SledStorage;
use client_common::tendermint::types::GenesisExt;
use client_common::tendermint::{Client, WebsocketRpcClient};
use client_common::{ErrorKind, Result};
#[cfg(not(feature = "mock-enc-dec"))]
use client_core::cipher::DefaultTransactionObfuscation;
#[cfg(feature = "mock-enc-dec")]
use client_core::cipher::MockAbciTransactionObfuscation;
use client_core::signer::WalletSignerManager;
use client_core::transaction_builder::DefaultWalletTransactionBuilder;
use client_core::wallet::syncer::ObfuscationSyncerConfig;
use client_core::wallet::DefaultWalletClient;
use client_network::network_ops::DefaultNetworkOpsClient;
use jsonrpc_core::{self, IoHandler};
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
#[cfg(feature = "mock-enc-dec")]
use log::warn;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "mock-enc-dec"))]
type AppTransactionCipher = DefaultTransactionObfuscation;
#[cfg(feature = "mock-enc-dec")]
type AppTransactionCipher = MockAbciTransactionObfuscation<WebsocketRpcClient>;
type AppTxBuilder = DefaultWalletTransactionBuilder<SledStorage, LinearFee, AppTransactionCipher>;
type AppWalletClient = DefaultWalletClient<SledStorage, WebsocketRpcClient, AppTxBuilder>;
type AppOpsClient = DefaultNetworkOpsClient<
    AppWalletClient,
    SledStorage,
    WebsocketRpcClient,
    LinearFee,
    AppTransactionCipher,
>;
type AppSyncerConfig =
    ObfuscationSyncerConfig<SledStorage, WebsocketRpcClient, AppTransactionCipher>;
pub(crate) struct Server {
    host: String,
    port: u16,
    network_id: u8,
    storage_dir: String,
    websocket_url: String,
    enable_fast_forward: bool,
    batch_size: usize,
}

/// normal
#[cfg(not(feature = "mock-enc-dec"))]
fn get_tx_query(tendermint_client: WebsocketRpcClient) -> Result<DefaultTransactionObfuscation> {
    DefaultTransactionObfuscation::from_tx_query(&tendermint_client)
}

/// temporary
#[cfg(feature = "mock-enc-dec")]
fn get_tx_query(
    tendermint_client: WebsocketRpcClient,
) -> Result<MockAbciTransactionObfuscation<WebsocketRpcClient>> {
    warn!("{}", "WARNING: Using mock (non-enclave) infrastructure");
    Ok(MockAbciTransactionObfuscation::new(tendermint_client))
}

impl Server {
    pub(crate) fn new(options: Options) -> Result<Server> {
        init_chain_id(&options.chain_id);
        let network_id = get_network_id();

        println!("Network type {:?} id {:02X}", get_network(), network_id);
        Ok(Server {
            host: options.host,
            port: options.port,
            network_id,
            storage_dir: options.storage_dir,
            websocket_url: options.websocket_url,
            enable_fast_forward: !options.disable_fast_forward,
            batch_size: options.batch_size,
        })
    }

    fn make_wallet_client(
        &self,
        storage: SledStorage,
        tendermint_client: WebsocketRpcClient,
    ) -> Result<AppWalletClient> {
        let signer_manager = WalletSignerManager::new(storage.clone());
        let transaction_cipher = get_tx_query(tendermint_client.clone())?;
        let transaction_builder = DefaultWalletTransactionBuilder::new(
            signer_manager,
            tendermint_client.genesis().unwrap().fee_policy(),
            transaction_cipher,
        );
        Ok(DefaultWalletClient::new(
            storage,
            tendermint_client,
            transaction_builder,
        ))
    }

    pub fn make_ops_client(
        &self,
        storage: SledStorage,
        tendermint_client: WebsocketRpcClient,
    ) -> Result<AppOpsClient> {
        let transaction_cipher = get_tx_query(tendermint_client.clone())?;
        let signer_manager = WalletSignerManager::new(storage.clone());
        let fee_algorithm = tendermint_client.genesis().unwrap().fee_policy();
        let wallet_client = self.make_wallet_client(storage, tendermint_client.clone())?;
        Ok(DefaultNetworkOpsClient::new(
            wallet_client,
            signer_manager,
            tendermint_client,
            fee_algorithm,
            transaction_cipher,
        ))
    }

    pub fn make_syncer_config(
        &self,
        storage: SledStorage,
        tendermint_client: WebsocketRpcClient,
    ) -> Result<AppSyncerConfig> {
        let transaction_cipher = get_tx_query(tendermint_client.clone())?;

        Ok(AppSyncerConfig::new(
            storage,
            tendermint_client,
            transaction_cipher,
            self.enable_fast_forward,
            self.batch_size,
        ))
    }

    pub fn start_client(
        &self,
        io: &mut IoHandler,
        storage: SledStorage,
        tendermint_client: WebsocketRpcClient,
    ) -> Result<()> {
        let multisig_rpc_wallet_client =
            self.make_wallet_client(storage.clone(), tendermint_client.clone())?;
        let multisig_rpc = MultiSigRpcImpl::new(multisig_rpc_wallet_client);

        let transaction_rpc = TransactionRpcImpl::new(self.network_id);

        let staking_rpc_wallet_client =
            self.make_wallet_client(storage.clone(), tendermint_client.clone())?;
        let ops_client = self.make_ops_client(storage.clone(), tendermint_client.clone())?;
        let staking_rpc =
            StakingRpcImpl::new(staking_rpc_wallet_client, ops_client, self.network_id);

        let syncer_config = self.make_syncer_config(storage.clone(), tendermint_client.clone())?;

        let sync_rpc = SyncRpcImpl::new(syncer_config);

        let wallet_rpc_wallet_client = self.make_wallet_client(storage, tendermint_client)?;
        let wallet_rpc = WalletRpcImpl::new(wallet_rpc_wallet_client, self.network_id);

        io.extend_with(multisig_rpc.to_delegate());
        io.extend_with(transaction_rpc.to_delegate());
        io.extend_with(staking_rpc.to_delegate());
        io.extend_with(sync_rpc.to_delegate());
        io.extend_with(wallet_rpc.to_delegate());
        Ok(())
    }

    pub(crate) fn start(&mut self) -> Result<()> {
        let mut io = IoHandler::new();
        let storage = SledStorage::new(&self.storage_dir)?;

        let tendermint_client = loop {
            match WebsocketRpcClient::new(&self.websocket_url) {
                Ok(client) => {
                    break Ok(client);
                }
                Err(error) => {
                    if ErrorKind::InitializationError == error.kind() {
                        log::error!("{:?}", error);
                    } else {
                        break Err(error);
                    }
                }
            }

            thread::sleep(Duration::from_secs(2));
        }?;

        self.start_client(&mut io, storage, tendermint_client)
            .unwrap();

        let server = ServerBuilder::new(io)
            // TODO: Either make CORS configurable or make it more strict
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Any,
            ]))
            .start_http(&SocketAddr::new(self.host.parse().unwrap(), self.port))
            .expect("Unable to start JSON-RPC server");

        log::info!("server wait");
        server.wait();

        Ok(())
    }
}

pub(crate) fn to_rpc_error<E: ToString + Debug>(error: E) -> jsonrpc_core::Error {
    log::error!("{:?}", error);
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: error.to_string(),
        data: None,
    }
}

pub(crate) fn rpc_error_from_string(error: String) -> jsonrpc_core::Error {
    log::error!("{}", error);
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: error,
        data: None,
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WalletRequest {
    pub name: String,
    pub passphrase: SecUtf8,
}
