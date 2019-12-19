use std::collections::BTreeSet;

use parity_scale_codec::{Decode, Encode};
use secstr::SecUtf8;

use chain_core::common::H256;
use chain_core::init::address::RedeemAddress;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::{Error, ErrorKind, PublicKey, Result, ResultExt, SecureStorage, Storage};

/// Key space of wallet
const KEYSPACE: &str = "core_wallet";

/// Wallet meta data
#[derive(Debug, Encode, Decode)]
pub struct Wallet {
    /// view key to decrypt enclave transactions
    pub view_key: PublicKey,
    /// public keys to construct transfer addresses
    pub public_keys: BTreeSet<PublicKey>,
    /// public keys of staking addresses
    pub staking_keys: BTreeSet<PublicKey>,
    /// root hashes of multi-sig transfer addresses
    pub root_hashes: BTreeSet<H256>,
}

impl Wallet {
    /// Creates a new instance of `Wallet`
    pub fn new(view_key: PublicKey) -> Self {
        Self {
            view_key,
            public_keys: Default::default(),
            staking_keys: Default::default(),
            root_hashes: Default::default(),
        }
    }

    /// Returns all staking addresses stored in a wallet
    pub fn staking_addresses(&self) -> BTreeSet<StakedStateAddress> {
        self.staking_keys
            .iter()
            .map(|public_key| StakedStateAddress::BasicRedeem(RedeemAddress::from(public_key)))
            .collect()
    }

    /// Returns all tree addresses stored in a wallet
    pub fn transfer_addresses(&self) -> BTreeSet<ExtendedAddr> {
        self.root_hashes
            .iter()
            .cloned()
            .map(ExtendedAddr::OrTree)
            .collect()
    }

    /// find staking key
    pub fn find_staking_key(&self, redeem_address: &RedeemAddress) -> Option<&PublicKey> {
        self.staking_keys
            .iter()
            .find(|staking_key| &RedeemAddress::from(*staking_key) == redeem_address)
    }

    /// find root hash
    pub fn find_root_hash(&self, address: &ExtendedAddr) -> Option<&H256> {
        match address {
            ExtendedAddr::OrTree(ref root_hash) => {
                self.root_hashes.iter().find(|hash| hash == &root_hash)
            }
        }
    }
}

/// Load wallet from storage
pub fn load_wallet<S: SecureStorage>(
    storage: &S,
    name: &str,
    passphrase: &SecUtf8,
) -> Result<Option<Wallet>> {
    storage.load_secure(KEYSPACE, name, passphrase)
}

/// Save wallet to storage
pub fn save_wallet<S: SecureStorage>(
    storage: &S,
    name: &str,
    passphrase: &SecUtf8,
    wallet: &Wallet,
) -> Result<()> {
    storage.save_secure(KEYSPACE, name, passphrase, wallet)
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

    /// Load wallet
    pub fn get_wallet(&self, name: &str, passphrase: &SecUtf8) -> Result<Wallet> {
        load_wallet(&self.storage, name, passphrase)?.err_kind(ErrorKind::InvalidInput, || {
            format!("Wallet with name ({}) not found", name)
        })
    }

    fn set_wallet(&self, name: &str, passphrase: &SecUtf8, wallet: Wallet) -> Result<()> {
        save_wallet(&self.storage, name, passphrase, &wallet)
    }

    /// Finds staking key corresponding to given redeem address
    pub fn find_staking_key(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        redeem_address: &RedeemAddress,
    ) -> Result<Option<PublicKey>> {
        Ok(self
            .get_wallet(name, passphrase)?
            .find_staking_key(redeem_address)
            .cloned())
    }

    /// Checks if root hash exists in current wallet and returns root hash if exists
    pub fn find_root_hash(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: &ExtendedAddr,
    ) -> Result<Option<H256>> {
        Ok(self
            .get_wallet(name, passphrase)?
            .find_root_hash(address)
            .copied())
    }

    /// Creates a new wallet and returns wallet ID
    pub fn create(&self, name: &str, passphrase: &SecUtf8, view_key: PublicKey) -> Result<()> {
        if self.storage.contains_key(KEYSPACE, name)? {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Wallet with name ({}) already exists", name),
            ));
        }

        self.set_wallet(name, passphrase, Wallet::new(view_key))
    }

    /// Returns view key of wallet
    pub fn view_key(&self, name: &str, passphrase: &SecUtf8) -> Result<PublicKey> {
        let wallet = self.get_wallet(name, passphrase)?;
        Ok(wallet.view_key)
    }

    /// Returns all public keys stored in a wallet
    pub fn public_keys(&self, name: &str, passphrase: &SecUtf8) -> Result<BTreeSet<PublicKey>> {
        let wallet = self.get_wallet(name, passphrase)?;
        Ok(wallet.public_keys)
    }

    /// Returns all public keys corresponding to staking addresses stored in a wallet
    pub fn staking_keys(&self, name: &str, passphrase: &SecUtf8) -> Result<BTreeSet<PublicKey>> {
        let wallet = self.get_wallet(name, passphrase)?;
        Ok(wallet.staking_keys)
    }

    /// Returns all multi-sig addresses stored in a wallet
    pub fn root_hashes(&self, name: &str, passphrase: &SecUtf8) -> Result<BTreeSet<H256>> {
        let wallet = self.get_wallet(name, passphrase)?;
        Ok(wallet.root_hashes)
    }

    /// Returns all staking addresses stored in a wallet
    pub fn staking_addresses(
        &self,
        name: &str,
        passphrase: &SecUtf8,
    ) -> Result<BTreeSet<StakedStateAddress>> {
        Ok(self.get_wallet(name, passphrase)?.staking_addresses())
    }

    /// Returns all tree addresses stored in a wallet
    pub fn transfer_addresses(
        &self,
        name: &str,
        passphrase: &SecUtf8,
    ) -> Result<BTreeSet<ExtendedAddr>> {
        Ok(self.get_wallet(name, passphrase)?.transfer_addresses())
    }

    /// Adds a public key to given wallet
    pub fn add_public_key(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        public_key: &PublicKey,
    ) -> Result<()> {
        self.modify_wallet(name, passphrase, move |wallet| {
            wallet.public_keys.insert(public_key.clone());
        })
    }

    /// Adds a public key corresponding to a staking address to given wallet
    pub fn add_staking_key(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        staking_key: &PublicKey,
    ) -> Result<()> {
        self.modify_wallet(name, passphrase, move |wallet| {
            wallet.staking_keys.insert(staking_key.clone());
        })
    }

    fn modify_wallet<F>(&self, name: &str, passphrase: &SecUtf8, f: F) -> Result<()>
    where
        F: Fn(&mut Wallet),
    {
        self.storage
            .fetch_and_update_secure(KEYSPACE, name, passphrase, move |value| {
                let mut wallet_bytes = value.chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        format!("Wallet with name ({}) not found", name),
                    )
                })?;
                let mut wallet = Wallet::decode(&mut wallet_bytes).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        format!("Unable to deserialize wallet with name {}", name),
                    )
                })?;
                f(&mut wallet);
                Ok(Some(wallet.encode()))
            })
            .map(|_| ())
    }

    /// Adds a multi-sig address to given wallet
    pub fn add_root_hash(&self, name: &str, passphrase: &SecUtf8, root_hash: H256) -> Result<()> {
        self.modify_wallet(name, passphrase, move |wallet| {
            wallet.root_hashes.insert(root_hash);
        })
    }

    /// Retrieves names of all the stored wallets
    pub fn names(&self) -> Result<Vec<String>> {
        let keys = self.storage.keys(KEYSPACE)?;

        keys.into_iter()
            .map(|bytes| {
                String::from_utf8(bytes).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize wallet names in storage",
                    )
                })
            })
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

        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        assert!(wallet_service
            .create("name", &passphrase, view_key.clone())
            .is_ok());

        let error = wallet_service
            .create("name", &SecUtf8::from("new_passphrase"), view_key.clone())
            .expect_err("Created duplicate wallet");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);

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

        assert_eq!(error.kind(), ErrorKind::InvalidInput, "Invalid error kind");

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

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
}
