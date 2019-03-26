use failure::ResultExt;
use hex::encode;
use zeroize::Zeroize;

use chain_core::init::address::RedeemAddress;

use crate::{ErrorKind, PrivateKey, PublicKey, Result, SecureStorage, Storage};

/// Exposes functionality for managing wallets
#[derive(Default)]
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
            let mut private_key = PrivateKey::new()?;
            let public_key = PublicKey::from(&private_key);

            private_key.zeroize();

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

#[cfg(test)]
mod tests {
    use super::WalletService;
    use crate::storage::SledStorage;
    use crate::ErrorKind;

    #[test]
    fn check_flow() {
        let wallet_service = WalletService::new(
            SledStorage::new("./wallet-service-test").expect("Unable to create sled storage"),
        );

        let wallet = wallet_service
            .get("name", "passphrase")
            .expect("Error while retrieving wallet information");

        assert!(wallet.is_none(), "Wallet is already present in storage");

        let wallet_id = wallet_service
            .create("name", "passphrase")
            .expect("Unable to create new wallet");

        let error = wallet_service
            .create("name", "passphrase_new")
            .expect_err("Able to create wallet with same name as previously created");

        assert_eq!(error.kind(), ErrorKind::AlreadyExists, "Invalid error kind");

        let wallet_id_new = wallet_service
            .get("name", "passphrase")
            .expect("Error while retrieving wallet information")
            .expect("Wallet with given name not found");

        assert_eq!(wallet_id, wallet_id_new, "Wallet ids should match");
    }
}
