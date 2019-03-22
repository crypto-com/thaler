use failure::ResultExt;
use hex::encode;

use chain_core::init::address::RedeemAddress;

use crate::{ErrorKind, PrivateKey, PublicKey, Result, SecureStorage, Storage};

/// Exposes functionality for managing wallets
pub struct WalletService<T> {
    storage: T,
}

impl<T> WalletService<T>
where
    T: Storage,
{
    /// Creates a new instance of wallet service
    pub fn new(storage: T) -> Self {
        WalletService { storage }
    }

    /// Creates a new wallet and returns wallet ID
    pub fn create(&self, name: &str, passphrase: &str) -> Result<String> {
        if self.storage.contains_key(name.as_bytes())? {
            Err(ErrorKind::AlreadyExists.into())
        } else {
            let private_key = PrivateKey::new()?;
            let public_key = PublicKey::from(&private_key);

            let address = RedeemAddress::from(&public_key);

            self.storage
                .set_secure(name.as_bytes(), address.0.to_vec(), passphrase.as_bytes())?;

            Ok(encode(address.0))
        }
    }

    /// Retrieves a wallet ID from storage
    pub fn get(&self, name: &str, passphrase: &str) -> Result<Option<String>> {
        let address = self
            .storage
            .get_secure(name.as_bytes(), passphrase.as_bytes())?;

        match address {
            None => Ok(None),
            Some(inner) => {
                let address =
                    RedeemAddress::try_from(&inner).context(ErrorKind::DeserializationError)?;
                Ok(Some(encode(address.0)))
            }
        }
    }
}
