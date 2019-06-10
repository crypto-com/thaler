use failure::ResultExt;
use hex;
use jsonrpc_http_server::jsonrpc_core;
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Value};
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use std::net::SocketAddr;

use client_common::error::{Error, ErrorKind, Result};
use client_common::storage::SledStorage;
use client_common::tendermint::{Client, RpcClient};
use client_core::signer::DefaultSigner;
use client_core::transaction_builder::DefaultTransactionBuilder;
use client_core::wallet::DefaultWalletClient;
use client_index::index::DefaultIndex;

use crate::wallet_rpc::{WalletRpc, WalletRpcImpl};
use crate::Options;

pub(crate) struct Server {
    host: String,
    port: u16,
    chain_id: u8,
    storage_dir: String,
    tendermint_url: String,
}

impl Server {
    pub(crate) fn new(options: Options) -> Result<Server> {
        let chain_id = hex::decode(&options.chain_id).context(ErrorKind::SerializationError)?[0];
        Ok(Server {
            host: options.host,
            port: options.port,
            chain_id,
            storage_dir: options.storage_dir,
            tendermint_url: options.tendermint_url,
        })
    }

    pub(crate) fn start(&self) -> Result<()> {
        let storage = SledStorage::new(&self.storage_dir)?;
        let tendermint_client = RpcClient::new(&self.tendermint_url);
        let signer = DefaultSigner::new(storage.clone());
        let transaction_builder =
            DefaultTransactionBuilder::new(signer, tendermint_client.genesis()?.fee_policy());
        let index = DefaultIndex::new(storage.clone(), tendermint_client);
        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .with_transaction_read(index)
            .with_transaction_write(transaction_builder)
            .build()?;
        let wallet_rpc = WalletRpcImpl::new(wallet_client, self.chain_id);

        let mut io = IoHandler::new();

        io.extend_with(wallet_rpc.to_delegate());
        io.add_method("say_hello", |_| Ok(Value::String("hello".into())));

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
