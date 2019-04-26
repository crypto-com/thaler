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

// #[cfg(test)]
// mod tests {
//     use super::*;

//     use client_core::{PrivateKey, PublicKey, WalletClient};
//     use chain_core::init::coin::Coin;
//     use chain_core::tx::data::address::ExtendedAddr;
//     use chain_core::tx::data::Tx;

//     #[derive(Default)]
//     pub struct MockClient;

//     impl WalletClient for MockClient {
//         fn wallets(&self) -> Result<Vec<String>> {
//             Ok("Default".to_owned())
//         }

//         /// Creates a new wallet with given name and returns wallet_id
//         fn new_wallet(&self, name: &str, passphrase: &str) -> Result<String> {
//             Ok("Default".to_owned())
//         }

//         /// Retrieves all public keys corresponding to given wallet
//         fn private_keys(&self, name: &str, passphrase: &str) -> Result<Vec<PrivateKey>> {
//             vec![PrivateKey::new()]
//         }

//         /// Retrieves all public keys corresponding to given wallet
//         fn public_keys(&self, name: &str, passphrase: &str) -> Result<Vec<PublicKey>> {
//             let private_key = PrivateKey::new();
//             vec![PublicKey::from(&private_key)]
//         }

//         /// Retrieves all addresses corresponding to given wallet
//         fn addresses(&self, name: &str, passphrase: &str) -> Result<Vec<ExtendedAddr>> {
//             vec![ExtendedAddr::BasicRedeem(
//                 RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
//             )]
//         }

//         /// Retrieves private key corresponding to given address
//         fn private_key(
//             &self,
//             name: &str,
//             passphrase: &str,
//             address: &ExtendedAddr,
//         ) -> Result<Option<PrivateKey>> {
//             PrivateKey::new()
//         }

//         /// Generates a new public key for given wallet
//         fn new_public_key(&self, name: &str, passphrase: &str) -> Result<PublicKey> {
//             PublicKey::from(&PrivateKey::new())
//         }

//         /// Generates a new address for given wallet
//         fn new_address(&self, name: &str, passphrase: &str) -> Result<ExtendedAddr> {
//             ExtendedAddr::BasicRedeem(
//                 RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
//             )
//         }

//         /// Retrieves current balance of wallet
//         fn balance(&self, name: &str, passphrase: &str) -> Result<Coin> {
//             Coin::zero()
//         }

//         /// Retrieves transaction history of wallet
//         fn history(&self, name: &str, passphrase: &str) -> Result<Vec<TransactionChange>> {
//             vec![]
//         }

//         /// Broadcasts a transaction to Crypto.com Chain
//         fn broadcast_transaction(&self, name: &str, passphrase: &str, transaction: Tx) -> Result<()> {
//             Ok(())
//         }

//         /// Synchronizes index with Crypto.com Chain (from last known height)
//         fn sync(&self) -> Result<()> {
//             Ok(())
//         }

//         /// Synchronizes index with Crypto.com Chain (from genesis)
//         fn sync_all(&self) -> Result<()> {
//             Ok(())
//         }
//     }

//     #[test]
//     fn create_should_create_wallet() => {
//         let wallet_rpc = WalletRpcImpl::new(MockClient::default());

//         assert!(wallet_rpc.create(WalletRequest {
//             name: "Default".to_owned(),
//             passphrase: "123456".to_owned(),
//         }.is_ok());
//     }
// }
