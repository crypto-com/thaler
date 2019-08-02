use failure::ResultExt;
use parity_scale_codec::{Decode, Encode};
use secstr::SecUtf8;

use chain_core::common::H256;
use chain_core::init::address::RedeemAddress;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::{Error, ErrorKind, PublicKey, Result, SecureStorage, Storage};

const KEYSPACE: &str = "core_wallet";

#[derive(Debug, Encode, Decode)]
struct Wallet {
    pub view_key: PublicKey,
    pub public_keys: Vec<PublicKey>,
    pub root_hashes: Vec<H256>,
}

impl Wallet {
    /// Creates a new instance of `Wallet`
    pub fn new(view_key: PublicKey) -> Self {
        Self {
            view_key,
            public_keys: Vec::new(),
            root_hashes: Vec::new(),
        }
    }
}

/// Maintains mapping `wallet-name -> wallet-details`
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
        let wallet_bytes = self
            .storage
            .get_secure(KEYSPACE, name, passphrase)?
            .ok_or_else(|| Error::from(ErrorKind::WalletNotFound))?;
        Wallet::decode(&mut wallet_bytes.as_slice())
            .context(ErrorKind::DeserializationError)
            .map_err(Into::into)
    }

    fn set_wallet(&self, name: &str, passphrase: &SecUtf8, wallet: Wallet) -> Result<()> {
        self.storage
            .set_secure(KEYSPACE, name, wallet.encode(), passphrase)?;

        Ok(())
    }

    /// Finds public key corresponding to given redeem address
    pub fn find_public_key(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        redeem_address: &RedeemAddress,
    ) -> Result<Option<PublicKey>> {
        let public_keys = self.public_keys(name, passphrase)?;

        for public_key in public_keys {
            let known_address = RedeemAddress::from(&public_key);

            if known_address == *redeem_address {
                return Ok(Some(public_key));
            }
        }

        Ok(None)
    }

    /// Checks if root hash exists in current wallet and returns root hash if exists
    pub fn find_root_hash(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: &ExtendedAddr,
    ) -> Result<Option<H256>> {
        let root_hashes = self.root_hashes(name, passphrase)?;

        match address {
            ExtendedAddr::OrTree(ref root_hash) => {
                for known_hash in root_hashes {
                    if known_hash == *root_hash {
                        return Ok(Some(known_hash));
                    }
                }

                Ok(None)
            }
        }
    }

    /// Creates a new wallet and returns wallet ID
    pub fn create(&self, name: &str, passphrase: &SecUtf8, view_key: PublicKey) -> Result<()> {
        if self.storage.contains_key(KEYSPACE, name)? {
            return Err(ErrorKind::AlreadyExists.into());
        }

        self.set_wallet(name, passphrase, Wallet::new(view_key))
    }

    /// Returns view key of wallet
    pub fn view_key(&self, name: &str, passphrase: &SecUtf8) -> Result<PublicKey> {
        let wallet = self.get_wallet(name, passphrase)?;
        Ok(wallet.view_key)
    }

    /// Returns all public keys stored in a wallet
    pub fn public_keys(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<PublicKey>> {
        let wallet = self.get_wallet(name, passphrase)?;
        Ok(wallet.public_keys)
    }

    /// Returns all multi-sig addresses stored in a wallet
    pub fn root_hashes(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<H256>> {
        let wallet = self.get_wallet(name, passphrase)?;
        Ok(wallet.root_hashes)
    }

    /// Returns all staking addresses stored in a wallet
    pub fn staking_addresses(
        &self,
        name: &str,
        passphrase: &SecUtf8,
    ) -> Result<Vec<StakedStateAddress>> {
        Ok(self
            .public_keys(name, passphrase)?
            .iter()
            .map(|public_key| StakedStateAddress::BasicRedeem(RedeemAddress::from(public_key)))
            .collect())
    }

    /// Returns all tree addresses stored in a wallet
    pub fn transfer_addresses(
        &self,
        name: &str,
        passphrase: &SecUtf8,
    ) -> Result<Vec<ExtendedAddr>> {
        Ok(self
            .root_hashes(name, passphrase)?
            .into_iter()
            .map(ExtendedAddr::OrTree)
            .collect())
    }

    /// Adds a public key to given wallet
    pub fn add_public_key(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        public_key: &PublicKey,
    ) -> Result<()> {
        self.storage
            .fetch_and_update_secure(KEYSPACE, name, passphrase, |value| {
                let mut wallet_bytes =
                    value.ok_or_else(|| Error::from(ErrorKind::WalletNotFound))?;
                let mut wallet =
                    Wallet::decode(&mut wallet_bytes).context(ErrorKind::DeserializationError)?;
                wallet.public_keys.push(public_key.clone());

                Ok(Some(wallet.encode()))
            })
            .map(|_| ())
    }

    /// Adds a multi-sig address to given wallet
    pub fn add_root_hash(&self, name: &str, passphrase: &SecUtf8, root_hash: H256) -> Result<()> {
        self.storage
            .fetch_and_update_secure(KEYSPACE, name, passphrase, |value| {
                let mut wallet_bytes =
                    value.ok_or_else(|| Error::from(ErrorKind::WalletNotFound))?;
                let mut wallet =
                    Wallet::decode(&mut wallet_bytes).context(ErrorKind::DeserializationError)?;
                wallet.root_hashes.push(root_hash);

                Ok(Some(wallet.encode()))
            })
            .map(|_| ())
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
    use client_common::PrivateKey;

    #[test]
    fn check_flow() {
        let wallet_service = WalletService::new(MemoryStorage::default());

        let passphrase = SecUtf8::from("passphrase");

        let private_key = PrivateKey::new().unwrap();
        let view_key = PublicKey::from(&private_key);

        let error = wallet_service
            .public_keys("name", &passphrase)
            .expect_err("Retrieved public keys for non-existent wallet");

        assert_eq!(error.kind(), ErrorKind::WalletNotFound);

        assert!(wallet_service
            .create("name", &passphrase, view_key.clone())
            .is_ok());

        let error = wallet_service
            .create("name", &SecUtf8::from("new_passphrase"), view_key.clone())
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
            .create("name", &SecUtf8::from("passphrase_new"), view_key)
            .expect_err("Able to create wallet with same name as previously created");

        assert_eq!(error.kind(), ErrorKind::AlreadyExists, "Invalid error kind");

        let private_key = PrivateKey::new().unwrap();
        let public_key = PublicKey::from(&private_key);

        wallet_service
            .add_public_key("name", &passphrase, &public_key)
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
