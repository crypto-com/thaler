#![cfg(feature = "sled")]

#[cfg(not(test))]
use std::path::Path;

use crate::service::{BalanceService, KeyService, WalletService};
use crate::storage::SledStorage;
use crate::{Chain, Result, Wallet};

const KEY_PATH: &str = "key";
const WALLET_PATH: &str = "wallet";
const BALANCE_PATH: &str = "balance";

/// Wallet backed by [`SledStorage`](crate::storage::SledStorage)
pub struct SledWallet<C> {
    chain: C,
    key_service: KeyService<SledStorage>,
    wallet_service: WalletService<SledStorage>,
    balance_service: BalanceService<C, SledStorage>,
}

impl<C> SledWallet<C>
where
    C: Chain + Clone,
{
    /// Creates a new instance with specified path for data storage'
    #[cfg(not(test))]
    pub fn new<P: AsRef<Path>>(path: P, chain: C) -> Result<Self> {
        let mut path_buf = path.as_ref().to_path_buf();
        path_buf.push(KEY_PATH);

        let key_storage = SledStorage::new(path_buf.as_path())?;
        let key_service = KeyService::new(key_storage);

        path_buf.pop();
        path_buf.push(WALLET_PATH);

        let wallet_storage = SledStorage::new(path_buf.as_path())?;
        let wallet_service = WalletService::new(wallet_storage);

        path_buf.pop();
        path_buf.push(BALANCE_PATH);

        let balance_storage = SledStorage::new(path_buf.as_path())?;
        let balance_service = BalanceService::new(chain.clone(), balance_storage);

        Ok(SledWallet {
            chain,
            key_service,
            wallet_service,
            balance_service,
        })
    }

    /// Creates a new instance with specified path for data storage'
    #[cfg(test)]
    pub fn new(path: String, chain: C) -> Result<Self> {
        let key_storage = SledStorage::new(path.clone() + KEY_PATH)?;
        let key_service = KeyService::new(key_storage);

        let wallet_storage = SledStorage::new(path.clone() + WALLET_PATH)?;
        let wallet_service = WalletService::new(wallet_storage);

        let balance_storage = SledStorage::new(path + BALANCE_PATH)?;
        let balance_service = BalanceService::new(chain.clone(), balance_storage);

        Ok(SledWallet {
            chain,
            key_service,
            wallet_service,
            balance_service,
        })
    }
}

impl<C> Wallet<C, SledStorage, SledStorage, SledStorage> for SledWallet<C>
where
    C: Chain,
{
    fn chain(&self) -> &C {
        &self.chain
    }

    fn key_service(&self) -> &KeyService<SledStorage> {
        &self.key_service
    }

    fn wallet_service(&self) -> &WalletService<SledStorage> {
        &self.wallet_service
    }

    fn balance_service(&self) -> &BalanceService<C, SledStorage> {
        &self.balance_service
    }
}

#[cfg(test)]
mod tests {
    use super::SledWallet;
    use crate::chain::MockChain;
    use crate::{ErrorKind, Wallet};

    #[test]
    fn check_happy_flow() {
        let wallet = SledWallet::new("./wallet-test".to_string(), MockChain::default())
            .expect("Unable to create sled wallet");

        wallet
            .new_wallet("name", "passphrase")
            .expect("Unable to create a new wallet");

        assert_eq!(
            None,
            wallet
                .get_addresses("name", "passphrase")
                .expect("Unable to get addresses for wallet"),
            "Wallet already has keys"
        );

        let address = wallet
            .generate_address("name", "passphrase")
            .expect("Unable to generate new address");

        let addresses = wallet
            .get_addresses("name", "passphrase")
            .expect("Unable to retrieve addresses")
            .expect("No addresses found");

        assert_eq!(1, addresses.len(), "Invalid addresses length");
        assert_eq!(address, addresses[0], "Addresses don't match");

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .get_public_keys("name_new", "passphrase")
                .expect_err("Found public keys for non existent wallet")
                .kind(),
            "Invalid public key present in database"
        );

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .generate_public_key("name_new", "passphrase")
                .expect_err("Generated public key for non existent wallet")
                .kind(),
            "Error of invalid kind received"
        );
    }
}
