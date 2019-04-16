#![cfg(all(feature = "sled", feature = "rpc"))]

use std::path::Path;

use failure::ResultExt;
use zeroize::Zeroize;

use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::{sum_coins, Coin};
use chain_core::tx::data::address::ExtendedAddr;
use client_common::balance::TransactionChange;
use client_common::storage::SledStorage;
use client_common::{ErrorKind, Result};
#[cfg(not(test))]
use client_index::index::RpcSledIndex;
use client_index::Index;

use crate::service::*;
#[cfg(test)]
use crate::tests::MockIndex;
use crate::{PublicKey, WalletClient};

/// Wallet client backed by `sled` embedded database and `RpcSledIndex`
pub struct RpcSledWalletClient {
    key_service: KeyService<SledStorage>,
    wallet_service: WalletService<SledStorage>,
    #[cfg(not(test))]
    index: RpcSledIndex,
    #[cfg(test)]
    index: MockIndex,
}

impl RpcSledWalletClient {
    /// Creates a new instance of `RpcSledWalletClient`
    pub fn new<P: AsRef<Path>>(path: P, url: &str) -> Result<Self> {
        #[cfg(not(test))]
        let storage = SledStorage::new(path.as_ref().to_path_buf())?;
        #[cfg(test)]
        let storage = SledStorage::temp(path.as_ref().to_path_buf())?;

        #[cfg(not(test))]
        let index = RpcSledIndex::new(path, url)?;
        #[cfg(test)]
        let index = MockIndex::new(path, url);

        Ok(RpcSledWalletClient {
            key_service: KeyService::new(storage.clone()),
            wallet_service: WalletService::new(storage),
            index,
        })
    }
}

impl WalletClient for RpcSledWalletClient {
    fn new_wallet(&self, name: &str, passphrase: &str) -> Result<String> {
        self.wallet_service.create(name, passphrase)
    }

    fn public_keys(&self, name: &str, passphrase: &str) -> Result<Vec<PublicKey>> {
        let wallet_id = self.wallet_service.get(name, passphrase)?;

        match wallet_id {
            None => Err(ErrorKind::WalletNotFound.into()),
            Some(wallet_id) => {
                let keys = self.key_service.get_keys(&wallet_id, passphrase)?;

                match keys {
                    None => Ok(Default::default()),
                    Some(keys) => {
                        let public_keys =
                            keys.iter().map(PublicKey::from).collect::<Vec<PublicKey>>();

                        Ok(public_keys)
                    }
                }
            }
        }
    }

    fn addresses(&self, name: &str, passphrase: &str) -> Result<Vec<ExtendedAddr>> {
        let public_keys = self.public_keys(name, passphrase)?;

        let addresses = public_keys
            .iter()
            .map(|public_key| ExtendedAddr::BasicRedeem(RedeemAddress::from(public_key)))
            .collect::<Vec<ExtendedAddr>>();

        Ok(addresses)
    }

    fn new_public_key(&self, name: &str, passphrase: &str) -> Result<PublicKey> {
        let wallet_id = self.wallet_service.get(name, passphrase)?;

        match wallet_id {
            None => Err(ErrorKind::WalletNotFound.into()),
            Some(wallet_id) => {
                let mut private_key = self.key_service.generate(&wallet_id, passphrase)?;
                let public_key = PublicKey::from(&private_key);

                private_key.zeroize();

                Ok(public_key)
            }
        }
    }

    fn new_address(&self, name: &str, passphrase: &str) -> Result<ExtendedAddr> {
        let public_key = self.new_public_key(name, passphrase)?;

        Ok(ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key)))
    }

    fn balance(&self, name: &str, passphrase: &str) -> Result<Coin> {
        let addresses = self.addresses(name, passphrase)?;

        let balances = addresses
            .iter()
            .map(|address| self.index.balance(address))
            .collect::<Result<Vec<Coin>>>()?;

        Ok(sum_coins(balances.into_iter()).context(ErrorKind::BalanceAdditionError)?)
    }

    fn history(&self, name: &str, passphrase: &str) -> Result<Vec<TransactionChange>> {
        let addresses = self.addresses(name, passphrase)?;

        let history = addresses
            .iter()
            .map(|address| self.index.transaction_changes(address))
            .collect::<Result<Vec<Vec<TransactionChange>>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<TransactionChange>>();

        Ok(history)
    }

    fn sync(&self) -> Result<()> {
        self.index.sync()
    }

    fn sync_all(&self) -> Result<()> {
        self.index.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_flow() {
        let wallet = RpcSledWalletClient::new("./wallet-test".to_string(), "dummy")
            .expect("Unable to create wallet client");

        assert!(wallet.addresses("name", "passphrase").is_err());

        wallet
            .new_wallet("name", "passphrase")
            .expect("Unable to create a new wallet");

        assert_eq!(0, wallet.addresses("name", "passphrase").unwrap().len());

        let address = wallet
            .new_address("name", "passphrase")
            .expect("Unable to generate new address");

        let addresses = wallet.addresses("name", "passphrase").unwrap();

        assert_eq!(1, addresses.len());
        assert_eq!(address, addresses[0], "Addresses don't match");

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .public_keys("name_new", "passphrase")
                .expect_err("Found public keys for non existent wallet")
                .kind(),
            "Invalid public key present in database"
        );

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .new_public_key("name_new", "passphrase")
                .expect_err("Generated public key for non existent wallet")
                .kind(),
            "Error of invalid kind received"
        );

        assert_eq!(
            Coin::new(30).unwrap(),
            wallet.balance("name", "passphrase").unwrap()
        );

        assert_eq!(1, wallet.history("name", "passphrase").unwrap().len());

        assert!(wallet.new_address("name", "passphrase").is_ok());

        assert_eq!(
            Coin::new(60).unwrap(),
            wallet.balance("name", "passphrase").unwrap()
        );

        assert_eq!(2, wallet.history("name", "passphrase").unwrap().len());

        assert!(wallet.history("new_name", "passphrase").is_err());
        assert!(wallet.balance("new_name", "passphrase").is_err());

        assert!(wallet.sync().is_ok());
        assert!(wallet.sync_all().is_ok());
    }
}
