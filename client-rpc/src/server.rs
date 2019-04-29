use hex;
use jsonrpc_http_server::jsonrpc_core;
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Value};
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use std::net::SocketAddr;
use failure::ResultExt;

use client_common::error::{Result, Error, ErrorKind};
use client_common::storage::SledStorage;
use client_common::tendermint::RpcClient;
use client_core::wallet::DefaultWalletClient;
use client_index::index::DefaultIndex;

use crate::wallet_rpc::{WalletRpc, WalletRpcImpl};

pub struct Server {
    host: String,
    port: u16,
    chain_id: u8,
}

impl Server {
    pub fn new(host: &str, port: u16, chain_id: &str) -> Result<Server>{
        let chain_id = hex::decode(chain_id).context(ErrorKind::SerializationError)?[0];
        Ok(Server {
            host: String::from(host),
            port,
            chain_id,
        })
    }

    pub fn start(&self) -> Result<()> {
        let storage = SledStorage::new(".storage")?;
        let tendermint_client = RpcClient::new("http://localhost:26657/");
        let index = DefaultIndex::new(storage.clone(), tendermint_client);
        let wallet_client = DefaultWalletClient::new(storage, index);
        let wallet_rpc = WalletRpcImpl::new(wallet_client.clone(), self.chain_id);

        let mut io = IoHandler::new();
        
        io.extend_with(wallet_rpc.to_delegate());
        io.add_method("say_hello", |_| {
            Ok(Value::String("hello".into()))
        });

        let server = ServerBuilder::new(io)
            .cors(DomainsValidation::AllowOnly(vec![AccessControlAllowOrigin::Any]))
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

pub(crate) fn rpc_error_string(error: String) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: error,
        data: None,
    }
}
