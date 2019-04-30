use jsonrpc_derive::rpc;
use jsonrpc_http_server::jsonrpc_core;
use serde::Deserialize;
use std::str::FromStr;

use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use client_common::balance::TransactionChange;
use client_core::wallet::WalletClient;

use crate::server::{rpc_error_from_string, to_rpc_error};

#[rpc]
pub trait WalletRpc {
    #[rpc(name = "wallet_addresses")]
    fn addresses(&self, request: WalletRequest) -> jsonrpc_core::Result<Vec<String>>;

    #[rpc(name = "wallet_balance")]
    fn balance(&self, request: WalletRequest) -> jsonrpc_core::Result<String>;

    #[rpc(name = "wallet_create")]
    fn create(&self, request: WalletRequest) -> jsonrpc_core::Result<String>;

    #[rpc(name = "wallet_list")]
    fn list(&self) -> jsonrpc_core::Result<Vec<String>>;

    #[rpc(name = "wallet_sendtoaddress")]
    fn sendtoaddress(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: String,
    ) -> jsonrpc_core::Result<()>;

    #[rpc(name = "sync")]
    fn sync(&self) -> jsonrpc_core::Result<()>;

    #[rpc(name = "sync_all")]
    fn sync_all(&self) -> jsonrpc_core::Result<()>;

    #[rpc(name = "wallet_transactions")]
    fn transactions(&self, request: WalletRequest) -> jsonrpc_core::Result<Vec<TransactionChange>>;
}

pub struct WalletRpcImpl<T: WalletClient + Send + Sync> {
    client: T,
    chain_id: u8,
}

impl<T> WalletRpcImpl<T>
where
    T: WalletClient + Send + Sync,
{
    pub fn new(client: T, chain_id: u8) -> Self {
        WalletRpcImpl { client, chain_id }
    }
}

impl<T> WalletRpc for WalletRpcImpl<T>
where
    T: WalletClient + Send + Sync + 'static,
{
    fn addresses(&self, request: WalletRequest) -> jsonrpc_core::Result<Vec<String>> {
        match self.client.addresses(&request.name, &request.passphrase) {
            Ok(addresses) => addresses
                .iter()
                .map(|address| match address {
                    ExtendedAddr::BasicRedeem(address) => Ok(format!("{}", address)),
                    _ => Err(rpc_error_from_string(
                        "Unsupported address format".to_owned(),
                    )),
                })
                .collect(),
            Err(e) => Err(to_rpc_error(e)),
        }
    }

    fn balance(&self, request: WalletRequest) -> jsonrpc_core::Result<String> {
        self.sync()?;

        match self.client.balance(&request.name, &request.passphrase) {
            Ok(balance) => Ok(format!("{}", *balance)),
            Err(e) => Err(to_rpc_error(e)),
        }
    }

    fn create(&self, request: WalletRequest) -> jsonrpc_core::Result<String> {
        if let Err(e) = self.client.new_wallet(&request.name, &request.passphrase) {
            return Err(to_rpc_error(e));
        }

        if let Err(e) = self.client.new_address(&request.name, &request.passphrase) {
            Err(to_rpc_error(e))
        } else {
            Ok(request.name.clone())
        }
    }

    fn list(&self) -> jsonrpc_core::Result<Vec<String>> {
        match self.client.wallets() {
            Ok(wallets) => Ok(wallets),
            Err(e) => Err(to_rpc_error(e)),
        }
    }

    fn sendtoaddress(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: String,
    ) -> jsonrpc_core::Result<()> {
        let amount: u64 = amount.parse::<u64>().map_err(|err| rpc_error_from_string(format!("{}", err)))?;
        self.sync()?;

        let redeem_address = RedeemAddress::from_str(&to_address[..])
            .map_err(|err| rpc_error_from_string(format!("{}", err)))?;
        let address = ExtendedAddr::BasicRedeem(redeem_address);
        let coin = Coin::new(amount).map_err(|err| rpc_error_from_string(format!("{}", err)))?;
        let tx_out = TxOut::new(address, coin);
        let tx_attributes = TxAttributes::new(self.chain_id);

        if let Err(e) = self.client.create_and_broadcast_transaction(
            &request.name,
            &request.passphrase,
            vec![tx_out],
            tx_attributes,
        ) {
            Err(to_rpc_error(e))
        } else {
            Ok(())
        }
    }

    fn sync(&self) -> jsonrpc_core::Result<()> {
        if let Err(e) = self.client.sync() {
            Err(to_rpc_error(e))
        } else {
            Ok(())
        }
    }

    fn sync_all(&self) -> jsonrpc_core::Result<()> {
        if let Err(e) = self.client.sync_all() {
            Err(to_rpc_error(e))
        } else {
            Ok(())
        }
    }

    fn transactions(&self, request: WalletRequest) -> jsonrpc_core::Result<Vec<TransactionChange>> {
        self.sync()?;

        match self.client.history(&request.name, &request.passphrase) {
            Ok(transaction_change) => Ok(transaction_change),
            Err(e) => Err(to_rpc_error(e)),
        }
    }
}

// TODO: should use secure string and cleared when no longer needed
#[derive(Debug, Deserialize)]
pub struct WalletRequest {
    name: String,
    passphrase: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::DateTime;
    use std::str::FromStr;
    use std::time::SystemTime;

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::attribute::TxAttributes;
    use chain_core::tx::data::input::TxoPointer;
    use chain_core::tx::data::output::TxOut;
    use chain_core::tx::data::{Tx, TxId};
    use client_common::balance::{BalanceChange, TransactionChange};
    use client_common::storage::MemoryStorage;
    use client_common::{Error, ErrorKind, Result};
    use client_core::wallet::DefaultWalletClient;
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

        fn unspent_transactions(&self, _address: &ExtendedAddr) -> Result<Vec<(TxoPointer, Coin)>> {
            Ok(Vec::new())
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
    fn test_create_duplicated_wallet() {
        let wallet_rpc = setup_wallet_rpc();

        assert_eq!(
            "Default".to_owned(),
            wallet_rpc
                .create(create_wallet_request("Default", "123456"))
                .unwrap()
        );

        assert_eq!(
            to_rpc_error(Error::from(ErrorKind::AlreadyExists)),
            wallet_rpc
                .create(create_wallet_request("Default", "123456"))
                .unwrap_err()
        );
    }

    #[test]
    fn test_create_and_list_wallet_flow() {
        let wallet_rpc = setup_wallet_rpc();

        assert_eq!(0, wallet_rpc.list().unwrap().len());

        assert_eq!(
            "Default".to_owned(),
            wallet_rpc
                .create(create_wallet_request("Default", "123456"))
                .unwrap()
        );

        assert_eq!(vec!["Default"], wallet_rpc.list().unwrap());

        assert_eq!(
            "Personal".to_owned(),
            wallet_rpc
                .create(create_wallet_request("Personal", "123456"))
                .unwrap()
        );

        let wallet_list = wallet_rpc.list().unwrap();
        assert_eq!(2, wallet_list.len());
        assert!(wallet_list.contains(&"Default".to_owned()));
        assert!(wallet_list.contains(&"Personal".to_owned()));
    }

    #[test]
    fn test_create_and_list_wallet_addresses_flow() {
        let wallet_rpc = setup_wallet_rpc();

        assert_eq!(
            to_rpc_error(Error::from(ErrorKind::WalletNotFound)),
            wallet_rpc
                .addresses(create_wallet_request("Default", "123456"))
                .unwrap_err()
        );

        assert_eq!(
            "Default".to_owned(),
            wallet_rpc
                .create(create_wallet_request("Default", "123456"))
                .unwrap()
        );

        assert_eq!(
            1,
            wallet_rpc
                .addresses(create_wallet_request("Default", "123456"))
                .unwrap()
                .len()
        );
    }

    #[test]
    fn test_wallet_balance() {
        let wallet_rpc = setup_wallet_rpc();

        wallet_rpc
            .create(create_wallet_request("Default", "123456"))
            .unwrap();
        assert_eq!(
            "30".to_owned(),
            wallet_rpc
                .balance(create_wallet_request("Default", "123456"))
                .unwrap()
        );
    }

    #[test]
    fn test_wallet_transactions() {
        let wallet_rpc = setup_wallet_rpc();

        wallet_rpc
            .create(create_wallet_request("Default", "123456"))
            .unwrap();
        assert_eq!(
            1,
            wallet_rpc
                .transactions(create_wallet_request("Default", "123456"))
                .unwrap()
                .len()
        );
    }

    #[test]
    fn test_wallet_sendtoaddress_with_invalid_amount() {
        let wallet_rpc = setup_wallet_rpc();

        wallet_rpc
            .create(create_wallet_request("Default", "123456"))
            .unwrap();
        let to_address = "0x066102dfe35f769dab65c54a0cc886c463ce2291".to_owned();
        let amount = "1234.1".to_owned();
        assert!(
            wallet_rpc
                .sendtoaddress(create_wallet_request("Default", "123456"), to_address, amount)
                .is_err()
        )
    }

    fn setup_wallet_rpc() -> WalletRpcImpl<DefaultWalletClient<MemoryStorage, MockIndex>> {
        let wallet_client =
            DefaultWalletClient::new(MemoryStorage::default(), MockIndex::default());
        let chain_id = 171u8;

        WalletRpcImpl::new(wallet_client, chain_id)
    }

    fn create_wallet_request(name: &str, passphrase: &str) -> WalletRequest {
        WalletRequest {
            name: name.to_owned(),
            passphrase: passphrase.to_owned(),
        }
    }
}
