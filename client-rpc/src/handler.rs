use jsonrpc_core::IoHandler;

use chain_core::tx::fee::FeeAlgorithm;
use client_common::cipher::TransactionObfuscation;
use client_common::storage::SledStorage;
use client_common::tendermint::WebsocketRpcClient;
use client_common::Result;
use client_core::service::HwKeyService;
use client_core::signer::WalletSignerManager;
use client_core::transaction_builder::DefaultWalletTransactionBuilder;
use client_core::wallet::syncer::{ObfuscationSyncerConfig, SyncerOptions};
use client_core::wallet::DefaultWalletClient;
use client_network::network_ops::DefaultNetworkOpsClient;

use crate::rpc::{
    info_rpc::{InfoRpc, InfoRpcImpl},
    multisig_rpc::{MultiSigRpc, MultiSigRpcImpl},
    staking_rpc::{StakingRpc, StakingRpcImpl},
    sync_rpc::{CBindingCore, SyncRpc, SyncRpcImpl},
    transaction_rpc::{TransactionRpc, TransactionRpcImpl},
    wallet_rpc::{WalletRpc, WalletRpcImpl},
};

type AppWalletClient<O, F> = DefaultWalletClient<
    SledStorage,
    WebsocketRpcClient,
    DefaultWalletTransactionBuilder<SledStorage, F, O>,
>;
type AppOpsClient<O, F> =
    DefaultNetworkOpsClient<AppWalletClient<O, F>, SledStorage, WebsocketRpcClient, F, O>;
type AppSyncerConfig<O> = ObfuscationSyncerConfig<SledStorage, WebsocketRpcClient, O>;

#[derive(Clone)]
pub struct RpcHandler {
    pub io: IoHandler,
}

impl RpcHandler {
    fn new_impl(
        storage_dir: &str,
        websocket_url: &str,
        network_id: u8,
        sync_options: SyncerOptions,
        progress_callback: Option<CBindingCore>,
    ) -> Result<Self> {
        let mut io = IoHandler::new();
        let storage = SledStorage::new(&storage_dir)?;
        let tendermint_client = WebsocketRpcClient::new(&websocket_url)?;
        let obfuscation = tendermint_client.clone();
        let fee_policy = tendermint_client.clone();

        let wallet_client = make_wallet_client(
            storage.clone(),
            tendermint_client.clone(),
            fee_policy.clone(),
            obfuscation.clone(),
        )?;
        let ops_client = make_ops_client(
            storage.clone(),
            tendermint_client.clone(),
            fee_policy.clone(),
            tendermint_client.clone(),
        )?;
        let syncer_config = AppSyncerConfig::new(
            storage.clone(),
            tendermint_client.clone(),
            obfuscation.clone(),
            sync_options,
        );

        let multisig_rpc = MultiSigRpcImpl::new(wallet_client.clone());
        let transaction_rpc = TransactionRpcImpl::new(network_id);
        let staking_rpc =
            StakingRpcImpl::new(wallet_client.clone(), ops_client.clone(), network_id);
        let info_rpc = InfoRpcImpl::new(ops_client);

        let sync_wallet_client =
            make_wallet_client(storage, tendermint_client, fee_policy, obfuscation)?;

        let sync_rpc = SyncRpcImpl::new(syncer_config, progress_callback, sync_wallet_client);
        let wallet_rpc = WalletRpcImpl::new(wallet_client, network_id);

        io.extend_with(multisig_rpc.to_delegate());
        io.extend_with(transaction_rpc.to_delegate());
        io.extend_with(staking_rpc.to_delegate());
        io.extend_with(sync_rpc.to_delegate());
        io.extend_with(wallet_rpc.to_delegate());
        io.extend_with(info_rpc.to_delegate());

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
        )
    }

    pub fn handle(&self, req: &str) -> Option<String> {
        self.io.handle_request_sync(req)
    }
}

fn make_wallet_client<O: TransactionObfuscation, F: FeeAlgorithm>(
    storage: SledStorage,
    tendermint_client: WebsocketRpcClient,
    fee_policy: F,
    obfuscator: O,
) -> Result<AppWalletClient<O, F>> {
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

fn make_ops_client<O: TransactionObfuscation, F: FeeAlgorithm>(
    storage: SledStorage,
    tendermint_client: WebsocketRpcClient,
    fee_policy: F,
    obfuscator: O,
) -> Result<AppOpsClient<O, F>> {
    let hw_key_service = HwKeyService::default();
    let signer_manager = WalletSignerManager::new(storage.clone(), hw_key_service);
    let wallet_client = make_wallet_client(
        storage,
        tendermint_client.clone(),
        fee_policy.clone(),
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
