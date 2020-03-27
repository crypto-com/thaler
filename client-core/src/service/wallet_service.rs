use indexmap::IndexSet;
use parity_scale_codec::{Decode, Encode, Input, Output};

use crate::service::{load_wallet_state, WalletState};
use crate::types::WalletKind;
use chain_core::common::H256;
use chain_core::init::address::RedeemAddress;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::{
    Error, ErrorKind, PrivateKey, PublicKey, Result, ResultExt, SecKey, SecureStorage, Storage,
};
use secstr::SecUtf8;
use serde::de::{self, Visitor};
use serde::export::PhantomData;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str;
/// Key space of wallet
const KEYSPACE: &str = "core_wallet";

fn get_public_keyspace(name: &str) -> String {
    format!("{}_{}_publickey", KEYSPACE, name)
}

fn get_stakingkey_keyspace(name: &str) -> String {
    format!("{}_{}_stakingkey", KEYSPACE, name)
}

fn get_stakingkeyset_keyspace(name: &str) -> String {
    format!("{}_{}_stakingkeyset", KEYSPACE, name)
}

fn get_private_keyspace(name: &str) -> String {
    format!("{}_{}_privatekey", KEYSPACE, name)
}

fn get_roothash_keyspace(name: &str) -> String {
    format!("{}_{}_roothash", KEYSPACE, name)
}

fn get_roothashset_keyspace(name: &str) -> String {
    format!("{}_{}_roothashset", KEYSPACE, name)
}

pub fn get_multisig_keyspace(name: &str) -> String {
    format!("{}_{}_multisigaddress", KEYSPACE, name)
}

fn get_info_keyspace(name: &str) -> String {
    format!("{}_{}_info", KEYSPACE, name)
}

fn get_wallet_keyspace() -> String {
    format!("{}_walletname", KEYSPACE)
}

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
#[derive(Debug, Clone)]
pub struct Wallet {
    /// view key to decrypt enclave transactions
    pub view_key: PublicKey,
    /// public keys of staking addresses
    pub staking_keys: IndexSet<PublicKey>,
    /// root hashes of multi-sig transfer addresses
    // this is transfer address
    pub root_hashes: IndexSet<H256>,
    /// wallet type
    pub wallet_kind: WalletKind,
}

impl Encode for Wallet {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.view_key.encode_to(dest);
    }
}

impl Decode for Wallet {
    fn decode<I: Input>(input: &mut I) -> std::result::Result<Self, parity_scale_codec::Error> {
        let view_key = PublicKey::decode(input)?;
        let staking_keys = IndexSet::new();
        let root_hashes = IndexSet::new();

        Ok(Wallet {
            view_key,
            staking_keys,
            root_hashes,
            wallet_kind: WalletKind::HD,
        })
    }
}

impl Wallet {
    /// Creates a new instance of `Wallet`
    pub fn new(view_key: PublicKey, wallet_kind: WalletKind) -> Self {
        Self {
            view_key,
            staking_keys: Default::default(),
            root_hashes: Default::default(),
            wallet_kind,
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
}

fn read_pubkey<S: SecureStorage>(storage: &S, keyspace: &str, key: &str) -> Result<PublicKey> {
    let value = storage.get(keyspace, key)?;
    if let Some(raw_value) = value {
        let pubkey = PublicKey::deserialize_from(&raw_value)?;
        Ok(pubkey)
    } else {
        Err(Error::new(ErrorKind::InvalidInput, "read pubkey error"))
    }
}

// compute index value to string from binary
// so that db iteration is the same with index_value
fn compute_key(index_value: u64) -> String {
    hex::encode(&u64::to_be_bytes(index_value as u64))
}

fn write_pubkey<S: SecureStorage>(
    storage: &S,
    keyspace: &str,
    key: &str,
    value: &PublicKey,
) -> Result<()> {
    storage.set(keyspace, key, value.serialize())?;
    Ok(())
}

fn read_pubkey_enc<S: SecureStorage>(
    storage: &S,
    keyspace: &str,
    key: &str,
    enckey: &SecKey,
) -> Result<PublicKey> {
    let value = storage.get_secure(keyspace, key, enckey)?;
    if let Some(raw_value) = value {
        let pubkey = PublicKey::deserialize_from(&raw_value)?;
        Ok(pubkey)
    } else {
        Err(Error::new(ErrorKind::InvalidInput, "read pubkey error"))
    }
}

fn write_pubkey_enc<S: SecureStorage>(
    storage: &S,
    keyspace: &str,
    key: &str,
    value: &PublicKey,
    enckey: &SecKey,
) -> Result<()> {
    storage.set_secure(keyspace, key, value.serialize(), enckey)?;
    Ok(())
}

fn read_string<S: SecureStorage>(storage: &S, keyspace: &str, key: &str) -> Result<String> {
    let value = storage.get(keyspace, key.as_bytes())?;
    if let Some(raw_value) = value {
        let ret = str::from_utf8(&raw_value).chain(|| {
            (
                ErrorKind::InvalidInput,
                "Unable to read string in wallet_service",
            )
        })?;
        Ok(ret.to_string())
    } else {
        Err(Error::new(ErrorKind::InvalidInput, "read string error"))
    }
}

fn read_number<S: SecureStorage>(
    storage: &S,
    keyspace: &str,
    key: &str,
    defaut_value: Option<u64>,
) -> Result<u64> {
    let value = storage.get(keyspace, key.as_bytes())?;
    if let Some(raw_value) = value {
        let mut v: [u8; 8] = [0; 8];
        v.copy_from_slice(&raw_value);
        let index_value: u64 = u64::from_le_bytes(v);
        return Ok(index_value);
    }

    if let Some(value) = defaut_value {
        Ok(value)
    } else {
        Err(Error::new(ErrorKind::InvalidInput, "read number error"))
    }
}

fn write_number<S: SecureStorage>(
    storage: &S,
    keyspace: &str,
    key: &str,
    value: u64,
) -> Result<()> {
    storage
        .set(keyspace, key.as_bytes(), value.to_le_bytes().to_vec())
        .expect("write storage");
    Ok(())
}

/// Load wallet from storage
pub fn load_wallet<S: SecureStorage>(
    storage: &S,
    name: &str,
    enckey: &SecKey,
) -> Result<Option<Wallet>> {
    let wallet: Option<Wallet> = storage.load_secure(KEYSPACE, name, enckey)?;

    if let Some(value) = wallet {
        let mut new_wallet = value;
        // storage -> wallet
        let info_keyspace = get_info_keyspace(name);
        new_wallet.view_key = read_pubkey_enc(storage, &info_keyspace, "viewkey", enckey)?;
        // pubkey
        let info_keyspace = format!("{}_{}_info", KEYSPACE, name);
        let staking_keyspace = get_stakingkey_keyspace(name);
        let stakingkey_count: u64 =
            read_number(storage, &info_keyspace, "stakingkeyindex", Some(0))?;
        for i in 0..stakingkey_count {
            let stakingkey = read_pubkey(storage, &staking_keyspace, &compute_key(i))?;
            new_wallet.staking_keys.insert(stakingkey);
        }

        // roothash
        let roothash_keyspace = get_roothash_keyspace(name);
        let roothash_count: u64 = read_number(storage, &info_keyspace, "roothashindex", Some(0))?;
        for i in 0..roothash_count {
            let value = storage.get(&roothash_keyspace, format!("{}", i))?;
            if let Some(raw_value) = value {
                let mut roothash_found: H256 = H256::default();
                roothash_found.copy_from_slice(&raw_value);
                new_wallet.root_hashes.insert(roothash_found);
            }
        }

        // load walletkind
        let walletkind: u64 = read_number(storage, &info_keyspace, "walletkind", Some(0))?;
        new_wallet.wallet_kind = walletkind.into();

        return Ok(Some(new_wallet));
    }

    Ok(None)
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
    // storage -> wallet
    pub fn get_wallet_state(&self, name: &str, enckey: &SecKey) -> Result<WalletState> {
        load_wallet_state(&self.storage, name, enckey)?.err_kind(ErrorKind::InvalidInput, || {
            format!("WalletState with name ({}) not found", name)
        })
    }

    /// Save wallet to storage
    pub fn save_wallet(&self, name: &str, enckey: &SecKey, wallet: &Wallet) -> Result<()> {
        self.storage.save_secure(KEYSPACE, name, enckey, wallet)?;

        let info_keyspace = get_info_keyspace(name);
        // write viewkey
        write_pubkey_enc(
            &self.storage,
            &info_keyspace,
            "viewkey",
            &wallet.view_key,
            enckey,
        )?;

        // stakingkey
        write_number(
            &self.storage,
            &info_keyspace,
            "walletkind",
            wallet.wallet_kind as u64,
        )?;
        write_number(&self.storage, &info_keyspace, "publicindex", 0)?;
        write_number(&self.storage, &info_keyspace, "stakingkeyindex", 0)?;
        for public_key in wallet.staking_keys.iter() {
            self.add_staking_key(name, enckey, public_key)?;
        }

        // root hash
        write_number(&self.storage, &info_keyspace, "roothashindex", 0)?;
        for root_hash in wallet.root_hashes.iter() {
            self.add_root_hash(name, enckey, root_hash.clone())?;
        }

        Ok(())
    }

    /// Store the wallet to storage
    // wallet -> storage
    pub fn set_wallet(&self, name: &str, enckey: &SecKey, wallet: Wallet) -> Result<()> {
        self.save_wallet(name, enckey, &wallet)
    }

    /// Finds staking key corresponding to given redeem address
    // TODO: change api not to use _enckey
    pub fn find_staking_key(
        &self,
        name: &str,
        _enckey: &SecKey,
        redeem_address: &RedeemAddress,
    ) -> Result<Option<PublicKey>> {
        let stakingkey_keyspace = get_stakingkeyset_keyspace(name);

        if let Ok(value) = read_pubkey(
            &self.storage,
            &stakingkey_keyspace,
            &redeem_address.to_string(),
        ) {
            Ok(Some(value))
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "finding staking"))
        }
    }

    /// Finds private_key corresponding to given public_key
    pub fn find_private_key(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<Option<PrivateKey>> {
        let private_keyspace = get_private_keyspace(name);

        // key: public_key
        // value: private_key
        let value = self
            .storage
            .get_secure(private_keyspace, public_key.serialize(), enckey)?;
        if let Some(raw_value) = value {
            let privatekey = PrivateKey::deserialize_from(&raw_value)?;
            Ok(Some(privatekey))
        } else {
            Err(Error::new(ErrorKind::InvalidInput, "private_key not found"))
        }
    }

    /// Checks if root hash exists in current wallet and returns root hash if exists
    // TODO: change api not to use _enckey
    pub fn find_root_hash(
        &self,
        name: &str,
        _enckey: &SecKey,
        address: &ExtendedAddr,
    ) -> Result<Option<H256>> {
        match address {
            ExtendedAddr::OrTree(ref root_hash) => {
                // roothashset
                let roothash_keyspace = get_roothashset_keyspace(name);

                let value = self
                    .storage
                    .get(roothash_keyspace, hex::encode(&root_hash))?;

                if let Some(raw_value) = value {
                    let mut roothash_found: H256 = H256::default();
                    roothash_found.copy_from_slice(&raw_value);

                    return Ok(Some(roothash_found));
                }
            }
        }

        Err(Error::new(ErrorKind::InvalidInput, "private_key not found"))
    }

    /// Creates a new wallet and returns wallet ID
    pub fn create(
        &self,
        name: &str,
        enckey: &SecKey,
        view_key: PublicKey,
        wallet_kind: WalletKind,
    ) -> Result<()> {
        if self.storage.contains_key(KEYSPACE, name)? {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Wallet with name ({}) already exists", name),
            ));
        }

        self.set_wallet(name, enckey, Wallet::new(view_key.clone(), wallet_kind))?;

        let info_keyspace = get_info_keyspace(name);
        // key: "viewkey"
        // value: view-key
        write_pubkey_enc(&self.storage, &info_keyspace, "viewkey", &view_key, enckey)?;

        // key: index
        // value: walletname
        let wallet_keyspace = get_wallet_keyspace();
        self.storage
            .set(wallet_keyspace, name, name.as_bytes().to_vec())?;

        Ok(())
    }

    /// Returns view key of wallet
    pub fn view_key(&self, name: &str, enckey: &SecKey) -> Result<PublicKey> {
        let _wallet_found = self.get_wallet(name, enckey)?;
        let info_keyspace = get_info_keyspace(name);
        read_pubkey_enc(&self.storage, &info_keyspace, "viewkey", enckey)
    }

    /// Returns all public keys stored in a wallet
    pub fn public_keys(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<PublicKey>> {
        if !self.storage.contains_key(KEYSPACE, name)? {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Wallet with name ({}) not found", name),
            ));
        }

        let _wallet_found = self.get_wallet(name, enckey)?;

        let public_keyspace = get_public_keyspace(name);

        let mut ret: IndexSet<PublicKey> = IndexSet::<PublicKey>::new();
        let info_keyspace = get_info_keyspace(name);
        let publickey_count: u64 = read_number(&self.storage, &info_keyspace, "publicindex", None)?;

        for i in 0..publickey_count {
            let pubkey = read_pubkey(&self.storage, &public_keyspace, &compute_key(i))?;
            ret.insert(pubkey);
        }
        Ok(ret)
    }

    /// Returns all public keys corresponding to staking addresses stored in a wallet
    pub fn staking_keys(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<PublicKey>> {
        if !self.storage.contains_key(KEYSPACE, name)? {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Wallet with name ({}) not found", name),
            ));
        }
        let _wallet_found = self.get_wallet(name, enckey)?;
        let stakingkey_keyspace = get_stakingkey_keyspace(name);
        let mut ret: IndexSet<PublicKey> = IndexSet::<PublicKey>::new();
        let info_keyspace = get_info_keyspace(name);
        let staking_count: u64 =
            read_number(&self.storage, &info_keyspace, "stakingkeyindex", None)?;
        for i in 0..staking_count {
            let pubkey = read_pubkey(&self.storage, &stakingkey_keyspace, &compute_key(i))?;
            ret.insert(pubkey);
        }
        Ok(ret)
    }

    /// Returns all staking addresses stored in a wallet
    pub fn staking_addresses(
        &self,
        name: &str,
        enckey: &SecKey,
    ) -> Result<IndexSet<StakedStateAddress>> {
        let pubkeys: IndexSet<PublicKey> = self.staking_keys(name, enckey)?;
        let mut ret: IndexSet<StakedStateAddress> = IndexSet::<StakedStateAddress>::new();
        for pubkey in &pubkeys {
            let staked = StakedStateAddress::BasicRedeem(RedeemAddress::from(pubkey));
            ret.insert(staked);
        }
        Ok(ret)
    }

    /// Returns all multi-sig addresses stored in a wallet
    pub fn root_hashes(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<H256>> {
        if !self.storage.contains_key(KEYSPACE, name)? {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Wallet with name ({}) not found", name),
            ));
        }
        let _wallet_found = self.get_wallet(name, enckey)?;
        let roothash_keyspace = get_roothash_keyspace(name);
        let mut ret: IndexSet<H256> = IndexSet::<H256>::new();
        let info_keyspace = get_info_keyspace(name);
        let roothash_count: u64 =
            read_number(&self.storage, &info_keyspace, "roothashindex", None)?;
        for i in 0..roothash_count {
            let value = self.storage.get(&roothash_keyspace, format!("{}", i))?;
            if let Some(raw_value) = value {
                let mut roothash_found: H256 = H256::default();
                roothash_found.copy_from_slice(&raw_value);
                ret.insert(roothash_found);
            }
        }
        Ok(ret)
    }

    /// Returns all tree addresses stored in a wallet
    pub fn transfer_addresses(
        &self,
        name: &str,
        enckey: &SecKey,
    ) -> Result<IndexSet<ExtendedAddr>> {
        let roothashes: IndexSet<H256> = self.root_hashes(name, enckey)?;
        let mut ret: IndexSet<ExtendedAddr> = IndexSet::<ExtendedAddr>::new();
        for roothash_found in &roothashes {
            let extended_addr = ExtendedAddr::OrTree(*roothash_found);
            ret.insert(extended_addr);
        }
        Ok(ret)
    }

    /// Adds a (public_key, private_key) pair to given wallet
    pub fn add_key_pairs(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
        private_key: &PrivateKey,
    ) -> Result<()> {
        let private_keyspace = get_private_keyspace(name);

        // key: public_key
        // value: private_key
        self.storage.set_secure(
            private_keyspace,
            public_key.serialize(),
            private_key.serialize(),
            enckey,
        )?;
        Ok(())
    }

    /// Adds a public key to given wallet
    // TODO: change api not to use _enckey
    pub fn add_public_key(
        &self,
        name: &str,
        _enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<()> {
        let public_keyspace = get_public_keyspace(name);
        let info_keyspace = get_info_keyspace(name);

        let mut index_value: u64 =
            read_number(&self.storage, &info_keyspace, "publicindex", Some(0))?;

        // key: index
        // value: publickey
        write_pubkey(
            &self.storage,
            &public_keyspace,
            &compute_key(index_value),
            &public_key,
        )?;

        index_value += 1;
        write_number(&self.storage, &info_keyspace, "publicindex", index_value)?;

        Ok(())
    }

    /// Adds a public key corresponding to a staking address to given wallet
    // TODO: change api not to use _enckey
    pub fn add_staking_key(
        &self,
        name: &str,
        _enckey: &SecKey,
        staking_key: &PublicKey,
    ) -> Result<()> {
        // stakingkey set
        // key: redeem address (20 bytes)
        // value: staking key (<-publickey)
        let redeemaddress = RedeemAddress::from(staking_key).to_string();
        let stakingkey_keyspace = get_stakingkey_keyspace(name);
        let stakingkeyset_keyspace = get_stakingkeyset_keyspace(name);
        let info_keyspace = get_info_keyspace(name);

        let mut index_value: u64 =
            read_number(&self.storage, &info_keyspace, "stakingkeyindex", Some(0))?;

        write_pubkey(
            &self.storage,
            &stakingkeyset_keyspace,
            &redeemaddress,
            &staking_key,
        )?;

        write_pubkey(
            &self.storage,
            &stakingkey_keyspace,
            &compute_key(index_value),
            &staking_key,
        )?;

        // increase
        index_value += 1;
        write_number(
            &self.storage,
            &info_keyspace,
            "stakingkeyindex",
            index_value,
        )?;

        Ok(())
    }

    /// Adds a multi-sig address to given wallet
    // TODO: change api not to use _enckey
    pub fn add_root_hash(&self, name: &str, _enckey: &SecKey, root_hash: H256) -> Result<()> {
        // roothashset
        let roothash_keyspace = get_roothash_keyspace(name);
        let roothashset_keyspace = get_roothashset_keyspace(name);
        let info_keyspace = get_info_keyspace(name);

        let mut index_value: u64 =
            read_number(&self.storage, &info_keyspace, "roothashindex", Some(0))?;

        // key: index
        // value: roothash
        self.storage.set(
            &roothash_keyspace,
            format!("{}", index_value),
            root_hash.to_vec(),
        )?;

        // roothashset
        self.storage.set(
            &roothashset_keyspace,
            hex::encode(&root_hash),
            root_hash.to_vec(),
        )?;

        // increase
        index_value += 1;
        write_number(&self.storage, &info_keyspace, "roothashindex", index_value)?;

        Ok(())
    }

    /// Retrieves names of all the stored wallets
    pub fn names(&self) -> Result<Vec<String>> {
        let wallet_keyspace = get_wallet_keyspace();
        let keys = self.storage.keys(&wallet_keyspace)?;
        let mut names: Vec<String> = vec![];
        for key in keys {
            let string_key = String::from_utf8(key).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to deserialize wallet names in storage",
                )
            })?;
            let name_found = read_string(&self.storage, &wallet_keyspace, &string_key)?;
            names.push(name_found);
        }
        Ok(names)
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        let wallet_keyspace = get_wallet_keyspace();
        let keys = self.storage.keys(&wallet_keyspace)?;
        for key in keys {
            let string_key = String::from_utf8(key).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to deserialize wallet names in storage",
                )
            })?;
            let name_found = read_string(&self.storage, &wallet_keyspace, &string_key)?;

            self.delete_wallet_keyspace(&name_found)?;
        }
        self.storage.clear(wallet_keyspace)?;
        self.storage.clear(KEYSPACE)?;

        Ok(())
    }

    fn delete_wallet_keyspace(&self, name: &str) -> Result<()> {
        self.storage.delete(KEYSPACE, name)?;
        assert!(self.storage.get(KEYSPACE, name)?.is_none());
        let info_keyspace = get_info_keyspace(name);

        let stakingkey_keyspace = get_stakingkey_keyspace(name);
        let stakingkeyset_keyspace = get_stakingkeyset_keyspace(name);
        let public_keyspace = get_public_keyspace(name);
        let private_keyspace = get_private_keyspace(name);
        let roothash_keyspace = get_roothash_keyspace(name);
        let roothashset_keyspace = get_roothashset_keyspace(name);
        let multisigaddress_keyspace = get_multisig_keyspace(name);
        let wallet_keyspace = get_wallet_keyspace();
        self.storage.delete(wallet_keyspace, name)?;
        self.storage.clear(info_keyspace)?;
        self.storage.clear(roothash_keyspace)?;
        self.storage.clear(roothashset_keyspace)?;
        self.storage.clear(stakingkey_keyspace)?;
        self.storage.clear(stakingkeyset_keyspace)?;
        self.storage.clear(public_keyspace)?;
        self.storage.clear(private_keyspace)?;
        self.storage.clear(multisigaddress_keyspace)?;
        Ok(())
    }
    /// Delete the key
    // TODO: change api not to use _enckey
    pub fn delete(&self, name: &str, enckey: &SecKey) -> Result<Wallet> {
        let wallet_found = self.get_wallet(name, enckey)?;
        self.storage.delete(KEYSPACE, name)?;
        self.delete_wallet_keyspace(name)?;
        Ok(wallet_found)
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

        let wallet_kind = WalletKind::Basic;

        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        assert!(wallet_service
            .create("name", &enckey, view_key.clone(), wallet_kind)
            .is_ok());

        let error = wallet_service
            .create("name", &enckey, view_key.clone(), wallet_kind)
            .expect_err("Created duplicate wallet");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        assert_eq!(
            0,
            wallet_service.public_keys("name", &enckey).unwrap().len()
        );

        let error = wallet_service
            .create("name", &enckey, view_key, wallet_kind)
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
