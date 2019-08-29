use failure::ResultExt;
use jsonrpc_core::{self, IoHandler};
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use chain_core::tx::fee::LinearFee;
use client_common::error::{Error, ErrorKind, Result};
use client_common::storage::SledStorage;
use client_common::tendermint::{Client, RpcClient};
use client_core::signer::DefaultSigner;
use client_core::transaction_builder::DefaultTransactionBuilder;
use client_core::wallet::DefaultWalletClient;
use client_index::cipher::MockAbciTransactionObfuscation;
use client_index::handler::{DefaultBlockHandler, DefaultTransactionHandler};
use client_index::index::DefaultIndex;
use client_index::synchronizer::ManualSynchronizer;
use client_network::network_ops::DefaultNetworkOpsClient;

use crate::rpc::multisig_rpc::{MultiSigRpc, MultiSigRpcImpl};
use crate::rpc::staking_rpc::{StakingRpc, StakingRpcImpl};
use crate::rpc::sync_rpc::{SyncRpc, SyncRpcImpl};
use crate::rpc::transaction_rpc::{TransactionRpc, TransactionRpcImpl};
use crate::rpc::wallet_rpc::{WalletRpc, WalletRpcImpl};
use crate::Options;
use chain_core::init::network::{
    get_network, get_network_id, init_chain_id, MAINNET_CHAIN_ID, TESTNET_CHAIN_ID,
};
type AppSigner = DefaultSigner<SledStorage>;
type AppIndex = DefaultIndex<SledStorage, RpcClient>;
type AppTransactionCipher = MockAbciTransactionObfuscation<RpcClient>;
type AppTxBuilder = DefaultTransactionBuilder<AppSigner, LinearFee, AppTransactionCipher>;
type AppWalletClient = DefaultWalletClient<SledStorage, AppIndex, AppTxBuilder>;
type AppOpsClient =
    DefaultNetworkOpsClient<AppWalletClient, AppSigner, RpcClient, LinearFee, AppTransactionCipher>;
type AppTransactionHandler = DefaultTransactionHandler<SledStorage>;
type AppBlockHandler =
    DefaultBlockHandler<AppTransactionCipher, AppTransactionHandler, SledStorage>;
type AppSynchronizer = ManualSynchronizer<SledStorage, RpcClient, AppBlockHandler>;

pub(crate) struct Server {
    host: String,
    port: u16,
    network_id: u8,
    storage_dir: String,
    tendermint_url: String,
}

impl Server {
    pub(crate) fn new(options: Options) -> Result<Server> {
        let network_id =
            hex::decode(&options.network_id).context(ErrorKind::SerializationError)?[0];
        let network_type = options.network_type;
        if network_type.len() < 4 {
            init_chain_id(&format!("dev-{}", options.network_id))
        } else {
            match &network_type[..4] {
                "main" => init_chain_id(MAINNET_CHAIN_ID),
                "test" => init_chain_id(TESTNET_CHAIN_ID),
                _ => init_chain_id(&format!("dev-{}", options.network_id)),
            }
        }
        println!(
            "Network type {:?}  id {:x}",
            get_network(),
            get_network_id()
        );
        Ok(Server {
            host: options.host,
            port: options.port,
            network_id,
            storage_dir: options.storage_dir,
            tendermint_url: options.tendermint_url,
        })
    }

    fn make_wallet_client(&self, storage: SledStorage) -> AppWalletClient {
        let tendermint_client = RpcClient::new(&self.tendermint_url);
        let signer = DefaultSigner::new(storage.clone());
        let transaction_cipher = MockAbciTransactionObfuscation::new(tendermint_client.clone());
        let transaction_builder = DefaultTransactionBuilder::new(
            signer,
            tendermint_client.genesis().unwrap().fee_policy(),
            transaction_cipher,
        );
        let index = DefaultIndex::new(storage.clone(), tendermint_client);
        DefaultWalletClient::builder()
            .with_wallet(storage)
            .with_transaction_read(index)
            .with_transaction_write(transaction_builder)
            .build()
            .unwrap()
    }

    pub fn make_ops_client(&self, storage: SledStorage) -> AppOpsClient {
        let tendermint_client = RpcClient::new(&self.tendermint_url);
        let transaction_cipher = MockAbciTransactionObfuscation::new(tendermint_client.clone());
        let signer = DefaultSigner::new(storage.clone());
        let fee_algorithm = tendermint_client.genesis().unwrap().fee_policy();
        let wallet_client = self.make_wallet_client(storage);
        DefaultNetworkOpsClient::new(
            wallet_client,
            signer,
            tendermint_client,
            fee_algorithm,
            transaction_cipher,
        )
    }

    pub fn make_synchronizer(&self, storage: SledStorage) -> AppSynchronizer {
        let tendermint_client = RpcClient::new(&self.tendermint_url);
        let transaction_cipher = MockAbciTransactionObfuscation::new(tendermint_client.clone());
        let transaction_handler = DefaultTransactionHandler::new(storage.clone());
        let block_handler =
            DefaultBlockHandler::new(transaction_cipher, transaction_handler, storage.clone());

        ManualSynchronizer::new(storage, tendermint_client, block_handler)
    }

    pub fn start_client(&self, io: &mut IoHandler, storage: SledStorage) -> Result<()> {
        let multisig_rpc_wallet_client = self.make_wallet_client(storage.clone());
        let multisig_rpc = MultiSigRpcImpl::new(multisig_rpc_wallet_client);

        let transaction_rpc = TransactionRpcImpl::new(self.network_id);

        let staking_rpc_wallet_client = self.make_wallet_client(storage.clone());
        let ops_client = self.make_ops_client(storage.clone());
        let staking_rpc =
            StakingRpcImpl::new(staking_rpc_wallet_client, ops_client, self.network_id);

        let sync_rpc_wallet_client = self.make_wallet_client(storage.clone());
        let synchronizer = self.make_synchronizer(storage.clone());
        let sync_rpc = SyncRpcImpl::new(sync_rpc_wallet_client, synchronizer);

        let wallet_rpc_wallet_client = self.make_wallet_client(storage.clone());
        let wallet_rpc = WalletRpcImpl::new(wallet_rpc_wallet_client, self.network_id);

        io.extend_with(multisig_rpc.to_delegate());
        io.extend_with(transaction_rpc.to_delegate());
        io.extend_with(staking_rpc.to_delegate());
        io.extend_with(sync_rpc.to_delegate());
        io.extend_with(wallet_rpc.to_delegate());
        Ok(())
    }

    pub(crate) fn start(&self) -> Result<()> {
        let mut io = IoHandler::new();
        let storage = SledStorage::new(&self.storage_dir)?;

        self.start_client(&mut io, storage.clone()).unwrap();

        let server = ServerBuilder::new(io)
            // TODO: Either make CORS configurable or make it more strict
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Any,
            ]))
            .start_http(&SocketAddr::new(self.host.parse().unwrap(), self.port))
            .expect("Unable to start JSON-RPC server");

        server.wait();

        Ok(())
    }
}

pub(crate) fn to_rpc_error(error: Error) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: error.to_string(),
        data: None,
    }
}

pub(crate) fn rpc_error_from_string(error: String) -> jsonrpc_core::Error {
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
