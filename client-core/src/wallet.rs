//! Wallet management
#[cfg(feature = "sled")]
mod sled_wallet;

#[cfg(feature = "sled")]
pub use self::sled_wallet::SledWallet;

use hex::encode;
use zeroize::Zeroize;

use chain_core::init::address::RedeemAddress;

use crate::service::{KeyService, WalletService};
use crate::{ErrorKind, PublicKey, Result, Storage};

/// Interface for a generic wallet
pub trait Wallet<K, W>
where
    K: Storage,
    W: Storage,
{
    /// Returns associated key service
    fn key_service(&self) -> &KeyService<K>;

    /// Returns associated wallet service
    fn wallet_service(&self) -> &WalletService<W>;

    /// Creates a new wallet with given name
    fn new_wallet(&self, name: &str, passphrase: &str) -> Result<String> {
        self.wallet_service().create(name, passphrase)
    }

    /// Retrieves all addresses corresponding to given wallet
    fn get_addresses(&self, name: &str, passphrase: &str) -> Result<Option<Vec<String>>> {
        let wallet_id = self.wallet_service().get(name, passphrase)?;

        match wallet_id {
            None => Ok(None),
            Some(wallet_id) => {
                let keys = self.key_service().get_keys(&wallet_id, passphrase)?;

                match keys {
                    None => Ok(None),
                    Some(keys) => {
                        let addresses: Vec<String> = keys
                            .into_iter()
                            .map(|mut private_key| {
                                let public_key = PublicKey::from(&private_key);
                                let address = RedeemAddress::from(&public_key);

                                private_key.zeroize();

                                encode(address.0)
                            })
                            .collect();

                        Ok(Some(addresses))
                    }
                }
            }
        }
    }

    /// Generates a new address
    fn generate_address(&self, name: &str, passphrase: &str) -> Result<String> {
        let wallet_id = self.wallet_service().get(name, passphrase)?;

        match wallet_id {
            None => Err(ErrorKind::WalletNotFound.into()),
            Some(wallet_id) => {
                let mut private_key = self.key_service().generate(&wallet_id, passphrase)?;
                let public_key = PublicKey::from(&private_key);
                let address = RedeemAddress::from(&public_key);

                private_key.zeroize();

                Ok(encode(address.0))
            }
        }
    }
}
