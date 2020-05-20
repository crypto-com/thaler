use jsonrpc_core::IoHandler;

use chain_core::tx::fee::LinearFee;
use client_common::storage::SledStorage;
use client_common::tendermint::{types::GenesisExt, Client, WebsocketRpcClient};
use client_common::Result;
use client_core::cipher::TransactionObfuscation;
use client_core::cipher::{mock::MockAbciTransactionObfuscation, DefaultTransactionObfuscation};
use client_core::service::HwKeyService;
use client_core::signer::WalletSignerManager;
use client_core::transaction_builder::DefaultWalletTransactionBuilder;
use client_core::wallet::syncer::{ObfuscationSyncerConfig, SyncerOptions};
use client_core::wallet::DefaultWalletClient;
use client_network::network_ops::DefaultNetworkOpsClient;

use crate::rpc::{
    multisig_rpc::{MultiSigRpc, MultiSigRpcImpl},
    staking_rpc::{StakingRpc, StakingRpcImpl},
    sync_rpc::{CBindingCore, SyncRpc, SyncRpcImpl},
    transaction_rpc::{TransactionRpc, TransactionRpcImpl},
    wallet_rpc::{WalletRpc, WalletRpcImpl},
};

type AppWalletClient<O> = DefaultWalletClient<
    SledStorage,
    WebsocketRpcClient,
    DefaultWalletTransactionBuilder<SledStorage, LinearFee, O>,
>;
type AppOpsClient<O> =
    DefaultNetworkOpsClient<AppWalletClient<O>, SledStorage, WebsocketRpcClient, LinearFee, O>;
type AppSyncerConfig<O> = ObfuscationSyncerConfig<SledStorage, WebsocketRpcClient, O>;

#[derive(Clone)]
pub struct RpcHandler {
    pub io: IoHandler,
}

impl RpcHandler {
    fn new_impl<O, F>(
        storage_dir: &str,
        websocket_url: &str,
        network_id: u8,
        sync_options: SyncerOptions,
        progress_callback: Option<CBindingCore>,
        get_obfuscator: F,
    ) -> Result<Self>
    where
        O: TransactionObfuscation + 'static,
        F: Fn(&WebsocketRpcClient) -> Result<O>,
    {
        let mut io = IoHandler::new();
        let storage = SledStorage::new(&storage_dir)?;
        let tendermint_client = WebsocketRpcClient::new(&websocket_url)?;
        let fee_policy = tendermint_client.genesis()?.fee_policy();
        let obfuscator: O = get_obfuscator(&tendermint_client)?;

        let wallet_client = make_wallet_client(
            storage.clone(),
            tendermint_client.clone(),
            fee_policy,
            obfuscator.clone(),
        )?;
        let ops_client = make_ops_client(
            storage.clone(),
            tendermint_client.clone(),
            fee_policy,
            obfuscator.clone(),
        )?;
        let syncer_config = AppSyncerConfig::new(
            storage.clone(),
            tendermint_client.clone(),
            obfuscator.clone(),
            sync_options,
        );

        let multisig_rpc = MultiSigRpcImpl::new(wallet_client.clone());
        let transaction_rpc = TransactionRpcImpl::new(network_id);
        let staking_rpc = StakingRpcImpl::new(wallet_client.clone(), ops_client, network_id);

        let sync_wallet_client =
            make_wallet_client(storage, tendermint_client, fee_policy, obfuscator)?;

        let sync_rpc = SyncRpcImpl::new(syncer_config, progress_callback, sync_wallet_client);
        let wallet_rpc = WalletRpcImpl::new(wallet_client, network_id);

        io.extend_with(multisig_rpc.to_delegate());
        io.extend_with(transaction_rpc.to_delegate());
        io.extend_with(staking_rpc.to_delegate());
        io.extend_with(sync_rpc.to_delegate());
        io.extend_with(wallet_rpc.to_delegate());

        Ok(RpcHandler { io })
    }

    pub fn new(
        storage_dir: &str,
        websocket_url: &str,
        network_id: u8,
        sync_options: SyncerOptions,
        progress_callback: Option<CBindingCore>,
    ) -> Result<Self> {
        Self::new_impl(
            storage_dir,
            websocket_url,
            network_id,
            sync_options,
            progress_callback,
            get_tx_query,
        )
    }

    pub fn new_mock(
        storage_dir: &str,
        websocket_url: &str,
        network_id: u8,
        sync_options: SyncerOptions,
        progress_callback: Option<CBindingCore>,
    ) -> Result<Self> {
        Self::new_impl(
            storage_dir,
            websocket_url,
            network_id,
            sync_options,
            progress_callback,
            get_tx_query_mock,
        )
    }

    pub fn handle(&self, req: &str) -> Option<String> {
        self.io.handle_request_sync(req)
    }
}

fn get_tx_query(tendermint_client: &WebsocketRpcClient) -> Result<impl TransactionObfuscation> {
    DefaultTransactionObfuscation::from_tx_query(tendermint_client)
}

fn get_tx_query_mock(
    tendermint_client: &WebsocketRpcClient,
) -> Result<impl TransactionObfuscation> {
    MockAbciTransactionObfuscation::from_tx_query(tendermint_client)
}

fn make_wallet_client<O: TransactionObfuscation>(
    storage: SledStorage,
    tendermint_client: WebsocketRpcClient,
    fee_policy: LinearFee,
    obfuscator: O,
) -> Result<AppWalletClient<O>> {
    let hw_key_service = HwKeyService::default();
    let signer_manager = WalletSignerManager::new(storage.clone(), hw_key_service.clone());
    Ok(DefaultWalletClient::new(
        storage,
        tendermint_client,
        DefaultWalletTransactionBuilder::new(signer_manager, fee_policy, obfuscator),
        Some(50),
        hw_key_service,
    ))
}

fn make_ops_client<O: TransactionObfuscation>(
    storage: SledStorage,
    tendermint_client: WebsocketRpcClient,
    fee_policy: LinearFee,
    obfuscator: O,
) -> Result<AppOpsClient<O>> {
    let hw_key_service = HwKeyService::default();
    let signer_manager = WalletSignerManager::new(storage.clone(), hw_key_service);
    let wallet_client = make_wallet_client(
        storage,
        tendermint_client.clone(),
        fee_policy,
        obfuscator.clone(),
    )?;
    Ok(DefaultNetworkOpsClient::new(
        wallet_client,
        signer_manager,
        tendermint_client,
        fee_policy,
        obfuscator,
    ))
}
