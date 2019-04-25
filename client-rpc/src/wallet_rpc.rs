use std::sync::Arc;

use chain_core::tx::data::address::ExtendedAddr;
use chain_core::init::coin::{Coin};
use client_core::wallet::{WalletClient};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::jsonrpc_core;
use serde::{Deserialize, Serialize};
use crate::server::{to_rpc_error, rpc_error_string};

#[rpc]
pub trait WalletRpc {
    #[rpc(name = "wallet_create")]
    fn create(&self, request: WalletRequest) -> jsonrpc_core::Result<bool>;

    #[rpc(name = "wallet_balance")]
    fn balance(&self, request: WalletRequest) -> jsonrpc_core::Result<Coin>;

    #[rpc(name = "wallet_addresses")]
    fn addresses(&self, request: WalletRequest) -> jsonrpc_core::Result<Vec<String>>;
}

pub struct WalletRpcImpl<T: WalletClient + Send + Sync> {
    client: T,
}

impl<T> WalletRpcImpl<T> where T: WalletClient + Send + Sync {
    pub fn new(client: T) -> Self {
        WalletRpcImpl { client }
    }
}

impl<T> WalletRpc for WalletRpcImpl<T> where T: WalletClient + Send + Sync + 'static {
    fn create(&self, request: WalletRequest) -> jsonrpc_core::Result<bool> {
        if let Err(e) = self.client.new_wallet(&request.name, &request.passphrase) {
            return Err(to_rpc_error(e))
        }

        if let Err(e) = self.client.new_address(&request.name, &request.passphrase) {
            Err(to_rpc_error(e))
        } else {
            Ok(true)
        }
    }

    fn balance(&self, request: WalletRequest) -> jsonrpc_core::Result<Coin> {
        match self.client.balance(&request.name, &request.passphrase) {
            Ok(balance) => Ok(balance),
            Err(e) => Err(to_rpc_error(e)),
        }
    }

    fn addresses(&self, request: WalletRequest) -> jsonrpc_core::Result<Vec<String>> {
        match self.client.addresses(&request.name, &request.passphrase) {
            Ok(addresses) => addresses.iter().map(|address| {
                match address {
                    ExtendedAddr::BasicRedeem(address) => Ok(format!("{}", address)),
                    _ => Err(rpc_error_string("Unrecognized adddress format".to_owned())),
                }
            }).collect(),
            Err(e) => Err(to_rpc_error(e)),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct WalletRequest {
    name: String,
    passphrase: String,
}

#[derive(Debug, Serialize)]
pub struct WalletResponse {
    name: String,
    balance: Coin,
    addresses: Vec<ExtendedAddr>,
}
