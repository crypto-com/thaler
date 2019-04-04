#![cfg(feature = "sled")]

use std::path::Path;

use crate::service::{BalanceService, KeyService, WalletService};
use crate::storage::SledStorage;
use crate::{Chain, Result, Wallet};

/// Wallet backed by [`SledStorage`](crate::storage::SledStorage)
pub struct SledWallet<C> {
    key_service: KeyService<SledStorage>,
    wallet_service: WalletService<SledStorage>,
    balance_service: BalanceService<C, SledStorage>,
}

impl<C> SledWallet<C>
where
    C: Chain + Clone,
{
    /// Creates a new instance with specified path for data storage'
    pub fn new<P: AsRef<Path>>(path: P, chain: C) -> Result<Self> {
        let storage = SledStorage::new(path)?;
        let key_service = KeyService::new(storage.clone());
        let wallet_service = WalletService::new(storage.clone());
        let balance_service = BalanceService::new(chain, storage);

        Ok(SledWallet {
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
