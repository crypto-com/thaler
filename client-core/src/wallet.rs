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
    /// Returns assiciated Crypto.com Chain client
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
            None => Ok(None),
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
}
