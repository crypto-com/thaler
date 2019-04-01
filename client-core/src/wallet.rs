//! Wallet management
#[cfg(feature = "sled")]
mod sled_wallet;

#[cfg(feature = "sled")]
pub use self::sled_wallet::SledWallet;

use hex::encode;
use zeroize::Zeroize;

use chain_core::init::address::RedeemAddress;

use crate::service::{BalanceService, KeyService, WalletService};
use crate::{Chain, ErrorKind, PublicKey, Result, Storage};

/// Interface for a generic wallet
pub trait Wallet<C, K, W, B>
where
    C: Chain,
    K: Storage,
    W: Storage,
    B: Storage,
{
    /// Returns associated Crypto.com Chain client
    fn chain(&self) -> &C;

    /// Returns associated key service
    fn key_service(&self) -> &KeyService<K>;

    /// Returns associated wallet service
    fn wallet_service(&self) -> &WalletService<W>;

    /// Returns associated balance service
    fn balance_service(&self) -> &BalanceService<C, B>;

    /// Creates a new wallet with given name
    fn new_wallet(&self, name: &str, passphrase: &str) -> Result<String> {
        self.wallet_service().create(name, passphrase)
    }

    /// Retrieves all public keys corresponding to given wallet
    fn get_public_keys(&self, name: &str, passphrase: &str) -> Result<Option<Vec<PublicKey>>> {
        let wallet_id = self.wallet_service().get(name, passphrase)?;

        match wallet_id {
            None => Err(ErrorKind::WalletNotFound.into()),
            Some(wallet_id) => {
                let keys = self.key_service().get_keys(&wallet_id, passphrase)?;

                match keys {
                    None => Ok(None),
                    Some(keys) => {
                        let public_keys: Vec<PublicKey> =
                            keys.iter().map(PublicKey::from).collect();

                        Ok(Some(public_keys))
                    }
                }
            }
        }
    }

    /// Retrieves all addresses corresponding to given wallet
    fn get_addresses(&self, name: &str, passphrase: &str) -> Result<Option<Vec<String>>> {
        let public_keys = self.get_public_keys(name, passphrase)?;

        let addresses = public_keys.map(|public_keys| {
            public_keys
                .iter()
                .map(|public_key| {
                    let address = RedeemAddress::from(public_key);
                    encode(address.0)
                })
                .collect::<Vec<String>>()
        });

        Ok(addresses)
    }

    /// Generates a new public key
    fn generate_public_key(&self, name: &str, passphrase: &str) -> Result<PublicKey> {
        let wallet_id = self.wallet_service().get(name, passphrase)?;

        match wallet_id {
            None => Err(ErrorKind::WalletNotFound.into()),
            Some(wallet_id) => {
                let mut private_key = self.key_service().generate(&wallet_id, passphrase)?;
                let public_key = PublicKey::from(&private_key);

                private_key.zeroize();

                Ok(public_key)
            }
        }
    }

    /// Generates a new address
    fn generate_address(&self, name: &str, passphrase: &str) -> Result<String> {
        let public_key = self.generate_public_key(name, passphrase)?;
        let address = RedeemAddress::from(&public_key);
        Ok(encode(address.0))
    }

    /// Retrieves current balance of wallet
    fn get_balance(&self, name: &str, passphrase: &str) -> Result<Option<u64>> {
        let wallet_id = self.wallet_service().get(name, passphrase)?;

        match wallet_id {
            None => Err(ErrorKind::WalletNotFound.into()),
            Some(wallet_id) => Ok(self
                .balance_service()
                .get_balance(&wallet_id, passphrase)?
                .map(Into::into)),
        }
    }

    /// Synchronizes and returns current balance of wallet
    fn sync_balance(&self, name: &str, passphrase: &str) -> Result<u64> {
        let addresses = self.get_addresses(name, passphrase)?;

        match addresses {
            None => Ok(0),
            Some(addresses) => {
                let wallet_id = self.wallet_service().get(name, passphrase)?;

                match wallet_id {
                    None => Err(ErrorKind::WalletNotFound.into()),
                    Some(wallet_id) => self
                        .balance_service()
                        .sync(&wallet_id, passphrase, addresses)
                        .map(Into::into),
                }
            }
        }
    }

    /// Recalculate current balance of wallet
    ///
    /// # Warning
    /// This should only be used when you need to recalculate balance from whole history of blockchain.
    fn recalculate_balance(&self, name: &str, passphrase: &str) -> Result<u64> {
        let addresses = self.get_addresses(name, passphrase)?;

        match addresses {
            None => Ok(0),
            Some(addresses) => {
                let wallet_id = self.wallet_service().get(name, passphrase)?;

                match wallet_id {
                    None => Err(ErrorKind::WalletNotFound.into()),
                    Some(wallet_id) => self
                        .balance_service()
                        .sync_all(&wallet_id, passphrase, addresses)
                        .map(Into::into),
                }
            }
        }
    }
}
