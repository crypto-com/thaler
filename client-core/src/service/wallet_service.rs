use indexmap::IndexSet;
use parity_scale_codec::{Decode, Encode, Input, Output};

use crate::service::{load_wallet_state, WalletState};
use chain_core::common::H256;
use chain_core::init::address::RedeemAddress;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::{
    Error, ErrorKind, PrivateKey, PublicKey, Result, ResultExt, SecKey, SecureStorage, Storage,
};
use std::fmt;
//use serde::ser::{Serialize, SerializeStruct, Serializer};
use secstr::SecUtf8;
use serde::de::{self, Visitor};
use serde::export::PhantomData;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Key space of wallet
const KEYSPACE: &str = "core_wallet";

fn serde_to_str<T, S>(value: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    T: Encode,
    S: Serializer,
{
    let value_str = base64::encode(&value.encode());
    serializer.serialize_str(&value_str)
}

fn deserde_from_str<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Decode,
{
    struct Helper<S>(PhantomData<S>);

    impl<'de, S> Visitor<'de> for Helper<S>
    where
        S: Decode,
    {
        type Value = S;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "expect valid str")
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            let raw_data = base64::decode(value).map_err(de::Error::custom)?;
            let v = Self::Value::decode(&mut raw_data.as_slice()).map_err(de::Error::custom)?;
            Ok(v)
        }
    }
    deserializer.deserialize_str(Helper(PhantomData))
}

/// Wallet information to export and import
#[derive(Debug, Deserialize, Serialize)]
pub struct WalletInfo {
    /// name of the the wallet
    pub name: String,
    /// wallet meta data
    #[serde(deserialize_with = "deserde_from_str", serialize_with = "serde_to_str")]
    pub wallet: Wallet,
    /// private key of the wallet
    #[serde(deserialize_with = "deserde_from_str", serialize_with = "serde_to_str")]
    pub private_key: PrivateKey,
    /// passphrase used when import wallet
    pub passphrase: Option<SecUtf8>,
}

/// Wallet meta data
#[derive(Debug)]
pub struct Wallet {
    /// view key to decrypt enclave transactions
    pub view_key: PublicKey,
    /// public keys to construct transfer addresses
    pub public_keys: IndexSet<PublicKey>,
    /// public keys of staking addresses
    pub staking_keys: IndexSet<PublicKey>,
    /// root hashes of multi-sig transfer addresses
    pub root_hashes: IndexSet<H256>,
}

impl Encode for Wallet {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.view_key.encode_to(dest);
        (self.public_keys.len() as u64).encode_to(dest);
        for key in self.public_keys.iter() {
            key.encode_to(dest);
        }
        (self.staking_keys.len() as u64).encode_to(dest);
        for key in self.staking_keys.iter() {
            key.encode_to(dest);
        }
        (self.root_hashes.len() as u64).encode_to(dest);
        for hash in self.root_hashes.iter() {
            hash.encode_to(dest);
        }
    }
}

impl Decode for Wallet {
    fn decode<I: Input>(input: &mut I) -> std::result::Result<Self, parity_scale_codec::Error> {
        let view_key = PublicKey::decode(input)?;

        let len = u64::decode(input)?;
        let mut public_keys = IndexSet::with_capacity(len as usize);
        for _ in 0..len {
            public_keys.insert(PublicKey::decode(input)?);
        }

        let len = u64::decode(input)?;
        let mut staking_keys = IndexSet::with_capacity(len as usize);
        for _ in 0..len {
            staking_keys.insert(PublicKey::decode(input)?);
        }

        let len = u64::decode(input)?;
        let mut root_hashes = IndexSet::with_capacity(len as usize);
        for _ in 0..len {
            root_hashes.insert(H256::decode(input)?);
        }

        Ok(Wallet {
            view_key,
            public_keys,
            staking_keys,
            root_hashes,
        })
    }
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
    pub fn staking_addresses(&self) -> IndexSet<StakedStateAddress> {
        self.staking_keys
            .iter()
            .map(|public_key| StakedStateAddress::BasicRedeem(RedeemAddress::from(public_key)))
            .collect()
    }

    /// Returns all tree addresses stored in a wallet
    pub fn transfer_addresses(&self) -> IndexSet<ExtendedAddr> {
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
    enckey: &SecKey,
) -> Result<Option<Wallet>> {
    storage.load_secure(KEYSPACE, name, enckey)
}

/// Save wallet to storage
pub fn save_wallet<S: SecureStorage>(
    storage: &S,
    name: &str,
    enckey: &SecKey,
    wallet: &Wallet,
) -> Result<()> {
    storage.save_secure(KEYSPACE, name, enckey, wallet)
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

    /// Get the wallet from storage
    pub fn get_wallet(&self, name: &str, enckey: &SecKey) -> Result<Wallet> {
        load_wallet(&self.storage, name, enckey)?.err_kind(ErrorKind::InvalidInput, || {
            format!("Wallet with name ({}) not found", name)
        })
    }

    /// Get the wallet state from storage
    pub fn get_wallet_state(&self, name: &str, enckey: &SecKey) -> Result<WalletState> {
        load_wallet_state(&self.storage, name, enckey)?.err_kind(ErrorKind::InvalidInput, || {
            format!("WalletState with name ({}) not found", name)
        })
    }

    /// Store the wallet to storage
    pub fn set_wallet(&self, name: &str, enckey: &SecKey, wallet: Wallet) -> Result<()> {
        save_wallet(&self.storage, name, enckey, &wallet)
    }

    /// Finds staking key corresponding to given redeem address
    pub fn find_staking_key(
        &self,
        name: &str,
        enckey: &SecKey,
        redeem_address: &RedeemAddress,
    ) -> Result<Option<PublicKey>> {
        Ok(self
            .get_wallet(name, enckey)?
            .find_staking_key(redeem_address)
            .cloned())
    }

    /// Checks if root hash exists in current wallet and returns root hash if exists
    pub fn find_root_hash(
        &self,
        name: &str,
        enckey: &SecKey,
        address: &ExtendedAddr,
    ) -> Result<Option<H256>> {
        Ok(self
            .get_wallet(name, enckey)?
            .find_root_hash(address)
            .copied())
    }

    /// Creates a new wallet and returns wallet ID
    pub fn create(&self, name: &str, enckey: &SecKey, view_key: PublicKey) -> Result<()> {
        if self.storage.contains_key(KEYSPACE, name)? {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Wallet with name ({}) already exists", name),
            ));
        }

        self.set_wallet(name, enckey, Wallet::new(view_key))
    }

    /// Returns view key of wallet
    pub fn view_key(&self, name: &str, enckey: &SecKey) -> Result<PublicKey> {
        let wallet = self.get_wallet(name, enckey)?;
        Ok(wallet.view_key)
    }

    /// Returns all public keys stored in a wallet
    pub fn public_keys(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<PublicKey>> {
        let wallet = self.get_wallet(name, enckey)?;
        Ok(wallet.public_keys)
    }

    /// Returns all public keys corresponding to staking addresses stored in a wallet
    pub fn staking_keys(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<PublicKey>> {
        let wallet = self.get_wallet(name, enckey)?;
        Ok(wallet.staking_keys)
    }

    /// Returns all multi-sig addresses stored in a wallet
    pub fn root_hashes(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<H256>> {
        let wallet = self.get_wallet(name, enckey)?;
        Ok(wallet.root_hashes)
    }

    /// Returns all staking addresses stored in a wallet
    pub fn staking_addresses(
        &self,
        name: &str,
        enckey: &SecKey,
    ) -> Result<IndexSet<StakedStateAddress>> {
        Ok(self.get_wallet(name, enckey)?.staking_addresses())
    }

    /// Returns all tree addresses stored in a wallet
    pub fn transfer_addresses(
        &self,
        name: &str,
        enckey: &SecKey,
    ) -> Result<IndexSet<ExtendedAddr>> {
        Ok(self.get_wallet(name, enckey)?.transfer_addresses())
    }

    /// Adds a public key to given wallet
    pub fn add_public_key(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<()> {
        self.modify_wallet(name, enckey, move |wallet| {
            wallet.public_keys.insert(public_key.clone());
        })
    }

    /// Adds a public key corresponding to a staking address to given wallet
    pub fn add_staking_key(
        &self,
        name: &str,
        enckey: &SecKey,
        staking_key: &PublicKey,
    ) -> Result<()> {
        self.modify_wallet(name, enckey, move |wallet| {
            wallet.staking_keys.insert(staking_key.clone());
        })
    }

    fn modify_wallet<F>(&self, name: &str, enckey: &SecKey, f: F) -> Result<()>
    where
        F: Fn(&mut Wallet),
    {
        self.storage
            .fetch_and_update_secure(KEYSPACE, name, enckey, move |value| {
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
    pub fn add_root_hash(&self, name: &str, enckey: &SecKey, root_hash: H256) -> Result<()> {
        self.modify_wallet(name, enckey, move |wallet| {
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

    /// Delete the key
    pub fn delete(&self, name: &str, enckey: &SecKey) -> Result<Wallet> {
        let wallet = self.get_wallet(name, enckey)?;
        self.storage.delete(KEYSPACE, name)?;
        Ok(wallet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secstr::SecUtf8;

    use client_common::storage::MemoryStorage;
    use client_common::{seckey::derive_enckey, PrivateKey};

    #[test]
    fn check_flow() {
        let wallet_service = WalletService::new(MemoryStorage::default());

        let enckey = derive_enckey(&SecUtf8::from("passphrase"), "name").unwrap();

        let private_key = PrivateKey::new().unwrap();
        let view_key = PublicKey::from(&private_key);

        let error = wallet_service
            .public_keys("name", &enckey)
            .expect_err("Retrieved public keys for non-existent wallet");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        assert!(wallet_service
            .create("name", &enckey, view_key.clone())
            .is_ok());

        let error = wallet_service
            .create("name", &enckey, view_key.clone())
            .expect_err("Created duplicate wallet");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        assert_eq!(
            0,
            wallet_service.public_keys("name", &enckey).unwrap().len()
        );

        let error = wallet_service
            .create("name", &enckey, view_key)
            .expect_err("Able to create wallet with same name as previously created");

        assert_eq!(error.kind(), ErrorKind::InvalidInput, "Invalid error kind");

        let private_key = PrivateKey::new().unwrap();
        let public_key = PublicKey::from(&private_key);

        wallet_service
            .add_public_key("name", &enckey, &public_key)
            .unwrap();

        assert_eq!(
            1,
            wallet_service.public_keys("name", &enckey).unwrap().len()
        );

        wallet_service.clear().unwrap();

        let error = wallet_service
            .public_keys("name", &enckey)
            .expect_err("Retrieved public keys for non-existent wallet");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
}
