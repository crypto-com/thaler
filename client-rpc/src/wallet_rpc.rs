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
    fn create(&self, request: WalletRequest) -> jsonrpc_core::Result<String>;

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
    fn create(&self, request: WalletRequest) -> jsonrpc_core::Result<String> {
        if let Err(e) = self.client.new_wallet(&request.name, &request.passphrase) {
            return Err(to_rpc_error(e))
        }

        if let Err(e) = self.client.new_address(&request.name, &request.passphrase) {
            Err(to_rpc_error(e))
        } else {
            Ok(request.name.clone())
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
                    _ => Err(rpc_error_string("Unsupported address format".to_owned())),
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
//     use chain_core::init::address::RedeemAddress;
//     use chain_core::init::coin::Coin;
//     use chain_core::tx::data::address::ExtendedAddr;
//     use chain_core::tx::data::Tx;
//     use client_common::Result;
//     use client_common::balance::TransactionChange;
//     use std::str::FromStr;

//     #[derive(Default)]
//     pub struct MockClient;

//     impl WalletClient for MockClient {
//         fn wallets(&self) -> Result<Vec<String>> {
//             Ok(vec!["Default".to_owned()])
//         }

//         /// Creates a new wallet with given name and returns wallet_id
//         fn new_wallet(&self, name: &str, passphrase: &str) -> Result<String> {
//             Ok("Default".to_owned())
//         }

//         /// Retrieves all public keys corresponding to given wallet
//         fn private_keys(&self, name: &str, passphrase: &str) -> Result<Vec<PrivateKey>> {
//             Ok(vec![PrivateKey::new().unwrap()])
//         }

//         /// Retrieves all public keys corresponding to given wallet
//         fn public_keys(&self, name: &str, passphrase: &str) -> Result<Vec<PublicKey>> {
//             let private_key = PrivateKey::new().unwrap();
//             Ok(vec![PublicKey::from(&private_key)])
//         }

//         /// Retrieves all addresses corresponding to given wallet
//         fn addresses(&self, name: &str, passphrase: &str) -> Result<Vec<ExtendedAddr>> {
//             Ok(vec![ExtendedAddr::BasicRedeem(
//                 RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
//             )])
//         }

//         /// Retrieves private key corresponding to given address
//         fn private_key(
//             &self,
//             name: &str,
//             passphrase: &str,
//             address: &ExtendedAddr,
//         ) -> Result<Option<PrivateKey>> {
//             Ok(Some(PrivateKey::new().unwrap()))
//         }

//         /// Generates a new public key for given wallet
//         fn new_public_key(&self, name: &str, passphrase: &str) -> Result<PublicKey> {
//             Ok(PublicKey::from(&PrivateKey::new().unwrap()))
//         }

//         /// Generates a new address for given wallet
//         fn new_address(&self, name: &str, passphrase: &str) -> Result<ExtendedAddr> {
//             Ok(ExtendedAddr::BasicRedeem(
//                 RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
//             ))
//         }

//         /// Retrieves current balance of wallet
//         fn balance(&self, name: &str, passphrase: &str) -> Result<Coin> {
//             Ok(Coin::zero())
//         }

//         /// Retrieves transaction history of wallet
//         fn history(&self, name: &str, passphrase: &str) -> Result<Vec<TransactionChange>> {
//             Ok(vec![])
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
//     fn create_should_create_wallet() {
//         let wallet_rpc = WalletRpcImpl::new(MockClient::default());

//         assert_eq!("Default".to_owned(), wallet_rpc.create(WalletRequest {
//             name: "Default".to_owned(),
//             passphrase: "123456".to_owned(),
//         }).unwrap());
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;
    use std::time::SystemTime;

    use chrono::DateTime;
    use client_core::wallet::DefaultWalletClient;
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::attribute::TxAttributes;
    use chain_core::tx::data::input::TxoPointer;
    use chain_core::tx::data::output::TxOut;
    use chain_core::tx::data::{Tx, TxId};
    use client_common::balance::{BalanceChange, TransactionChange};
    use client_common::storage::MemoryStorage;
    use client_common::{Storage, Error, ErrorKind, Result};
    use client_index::Index;

    #[derive(Default)]
    pub struct MockIndex;

    impl Index for MockIndex {
        fn sync(&self) -> Result<()> {
            Ok(())
        }

        fn sync_all(&self) -> Result<()> {
            Ok(())
        }

        fn transaction_changes(&self, address: &ExtendedAddr) -> Result<Vec<TransactionChange>> {
            Ok(vec![TransactionChange {
                transaction_id: TxId::zero(),
                address: address.clone(),
                balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                height: 1,
                time: DateTime::from(SystemTime::now()),
            }])
        }

        fn balance(&self, _: &ExtendedAddr) -> Result<Coin> {
            Ok(Coin::new(30).unwrap())
        }

        fn transaction(&self, _: &TxId) -> Result<Option<Tx>> {
            Ok(Some(Tx {
                inputs: vec![TxoPointer {
                    id: TxId::zero(),
                    index: 1,
                }],
                outputs: Default::default(),
                attributes: TxAttributes::new(171),
            }))
        }

        fn output(&self, _id: &TxId, _index: usize) -> Result<TxOut> {
            Ok(TxOut {
                address: ExtendedAddr::BasicRedeem(
                    RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
                ),
                value: Coin::new(10000000000000000000).unwrap(),
                valid_from: None,
            })
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn create_should_create_new_address_in_the_newly_created_wallet() {
        let memory_storage = MemoryStorage::default();
        let wallet_client = DefaultWalletClient::new(memory_storage, MockIndex::default());
        let wallet_rpc = WalletRpcImpl::new(wallet_client);

        assert_eq!(
            to_rpc_error(Error::from(ErrorKind::WalletNotFound)),
            wallet_rpc.addresses(new_wallet_request("Default", "123456")).unwrap_err()
        );

        assert_eq!(
            "Default".to_owned(),
            wallet_rpc.create(new_wallet_request("Default", "123456")).unwrap()
        );

        assert_eq!(1, wallet_rpc.addresses(new_wallet_request("Default", "123456")).unwrap().len());
    }

    fn new_wallet_request(name: &str, passphrase: &str) -> WalletRequest {
        WalletRequest {
            name: name.to_owned(),
            passphrase: passphrase.to_owned(),
        }
    }
}

