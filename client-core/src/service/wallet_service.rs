use failure::ResultExt;
use parity_codec::{Decode, Encode};
use secstr::SecUtf8;

use chain_core::common::H256;
use client_common::{ErrorKind, Result, SecureStorage, Storage};

use crate::PublicKey;

const KEYSPACE: &str = "core_wallet";

#[derive(Debug, Default, Encode, Decode)]
struct Wallet {
    pub public_keys: Vec<PublicKey>,
    pub multi_sig_addresses: Vec<H256>,
}

/// Maintains mapping `wallet-name -> Vec<wallet>`
#[derive(Debug, Default, Clone)]
pub struct WalletService<T: Storage> {
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

    fn get_wallet(&self, name: &str, passphrase: &SecUtf8) -> Result<Wallet> {
        let wallet_bytes = self.storage.get_secure(KEYSPACE, name, passphrase)?;

        match wallet_bytes {
            None => Err(ErrorKind::WalletNotFound.into()),
            Some(wallet_bytes) => Wallet::decode(&mut wallet_bytes.as_slice())
                .ok_or_else(|| client_common::Error::from(ErrorKind::DeserializationError)),
        }
    }

    fn set_wallet(&self, name: &str, passphrase: &SecUtf8, wallet: Wallet) -> Result<()> {
        self.storage
            .set_secure(KEYSPACE, name, wallet.encode(), passphrase)?;

        Ok(())
    }

    /// Creates a new wallet and returns wallet ID
    pub fn create(&self, name: &str, passphrase: &SecUtf8) -> Result<()> {
        if self.storage.contains_key(KEYSPACE, name)? {
            Err(ErrorKind::AlreadyExists.into())
        } else {
            self.set_wallet(name, passphrase, Wallet::default())
        }
    }

    /// Returns all public keys stored in a wallet
    pub fn public_keys(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<PublicKey>> {
        let wallet = self.get_wallet(name, passphrase)?;
        Ok(wallet.public_keys)
    }

    /// Returns all multi-sig addresses stored in a wallet
    pub fn multi_sig_addresses(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<H256>> {
        let wallet = self.get_wallet(name, passphrase)?;
        Ok(wallet.multi_sig_addresses)
    }

    /// Adds a public key to given wallet
    pub fn add_public_key(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        public_key: PublicKey,
    ) -> Result<()> {
        let mut wallet = self.get_wallet(name, passphrase)?;
        wallet.public_keys.push(public_key);
        self.set_wallet(name, passphrase, wallet)
    }

    /// Adds a multi-sig address to given wallet
    pub fn add_multi_sig_address(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: H256,
    ) -> Result<()> {
        let mut wallet = self.get_wallet(name, passphrase)?;
        wallet.multi_sig_addresses.push(address);
        self.set_wallet(name, passphrase, wallet)
    }

    /// Retrieves names of all the stored wallets
    pub fn names(&self) -> Result<Vec<String>> {
        let keys = self.storage.keys(KEYSPACE)?;

        keys.into_iter()
            .map(|bytes| Ok(String::from_utf8(bytes).context(ErrorKind::DeserializationError)?))
            .collect()
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use client_common::storage::MemoryStorage;

    use crate::PrivateKey;

    #[test]
    fn check_flow() {
        let wallet_service = WalletService::new(MemoryStorage::default());

        let passphrase = SecUtf8::from("passphrase");

        let error = wallet_service
            .public_keys("name", &passphrase)
            .expect_err("Retrieved public keys for non-existent wallet");

        assert_eq!(error.kind(), ErrorKind::WalletNotFound);

        assert!(wallet_service.create("name", &passphrase).is_ok());

        let error = wallet_service
            .create("name", &SecUtf8::from("new_passphrase"))
            .expect_err("Created duplicate wallet");

        assert_eq!(error.kind(), ErrorKind::AlreadyExists);

        assert_eq!(
            0,
            wallet_service
                .public_keys("name", &passphrase)
                .unwrap()
                .len()
        );

        let error = wallet_service
            .create("name", &SecUtf8::from("passphrase_new"))
            .expect_err("Able to create wallet with same name as previously created");

        assert_eq!(error.kind(), ErrorKind::AlreadyExists, "Invalid error kind");

        let private_key = PrivateKey::new().unwrap();
        let public_key = PublicKey::from(&private_key);

        wallet_service
            .add_public_key("name", &passphrase, public_key)
            .unwrap();

        assert_eq!(
            1,
            wallet_service
                .public_keys("name", &passphrase)
                .unwrap()
                .len()
        );

        wallet_service.clear().unwrap();

        let error = wallet_service
            .public_keys("name", &passphrase)
            .expect_err("Retrieved public keys for non-existent wallet");

        assert_eq!(error.kind(), ErrorKind::WalletNotFound);
    }
}
