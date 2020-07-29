use indexmap::IndexSet;
use parity_scale_codec::{Decode, Encode, Input, Output};

use crate::hd_wallet::ChainPath;
use crate::service::{load_wallet_state, HdKey, WalletState};
use crate::types::WalletKind;
use chain_core::common::H256;
use chain_core::init::address::RedeemAddress;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::{
    Error, ErrorKind, MultiSigAddress, PrivateKey, PublicKey, Result, ResultExt, SecKey,
    SecureStorage, Storage,
};
use secstr::SecUtf8;
use serde::de::{self, Visitor};
use serde::export::PhantomData;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
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

fn get_hdpath_keyspace(name: &str) -> String {
    format!("{}_{}_hdpath", KEYSPACE, name)
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
#[derive(Deserialize, Serialize)]
pub struct WalletInfo {
    /// name of the the wallet
    pub name: String,
    /// wallet meta data
    #[serde(deserialize_with = "deserde_from_str", serialize_with = "serde_to_str")]
    pub wallet: Wallet,
    /// private key of view key pair
    #[serde(deserialize_with = "deserde_from_str", serialize_with = "serde_to_str")]
    pub private_key: PrivateKey,
    /// passphrase used when import wallet
    pub passphrase: Option<SecUtf8>,
    ///public_key -> encoded private_key pairs, private key is None for hardware wallet
    #[serde(deserialize_with = "deserde_from_str", serialize_with = "serde_to_str")]
    pub key_pairs: BTreeMap<PublicKey, PrivateKey>,
    /// public_key -> hd path pairs for hardware wallet
    #[serde(deserialize_with = "deserde_from_str", serialize_with = "serde_to_str")]
    pub key_chainpath: BTreeMap<PublicKey, String>,
    /// hdkey for hd wallet and hw wallet
    #[serde(deserialize_with = "deserde_from_str", serialize_with = "serde_to_str")]
    pub hdkey: Option<HdKey>,
    /// hex encoded root_hash -> parity_scale_codec encoded multisig_address pairs
    #[serde(deserialize_with = "deserde_from_str", serialize_with = "serde_to_str")]
    pub multisig_address_pair: BTreeMap<String, MultiSigAddress>,

    /// staking keys
    #[serde(deserialize_with = "deserde_from_str", serialize_with = "serde_to_str")]
    pub staking_keys: Vec<PublicKey>,
}

use std::sync::{Arc, Mutex};

/// proxy for the storage
pub trait WalletStorage: Send + Sync {
    fn staking_addresses_contains(
        &self,
        name: &str,
        enckey: &SecKey,
        addr: &StakedStateAddress,
    ) -> Result<bool>;
    fn transfer_addresses_contains(
        &self,
        name: &str,
        enckey: &SecKey,
        addr: &ExtendedAddr,
    ) -> Result<bool>;
    fn get_public_keys(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<PublicKey>>;
    fn get_roothashes(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<H256>>;
}

/// create temp wallet storage for direct db access
pub struct WalletStorageImpl<T: Storage> {
    storage: T,
}
impl<T> WalletStorageImpl<T>
where
    T: Storage + 'static,
{
    /// create temp wallet storage
    pub fn new(storage: T) -> Self {
        WalletStorageImpl { storage }
    }
}
impl<T> WalletStorage for WalletStorageImpl<T>
where
    T: Storage + 'static,
{
    fn staking_addresses_contains(
        &self,
        name: &str,
        _enckey: &SecKey,
        redeem_address: &StakedStateAddress,
    ) -> Result<bool> {
        let stakingkey_keyspace = get_stakingkeyset_keyspace(name);

        if let Ok(_value) = read_pubkey(
            &self.storage,
            &stakingkey_keyspace,
            &redeem_address.to_string(),
        ) {
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn transfer_addresses_contains(
        &self,
        name: &str,
        _enckey: &SecKey,
        address: &ExtendedAddr,
    ) -> Result<bool> {
        match address {
            ExtendedAddr::OrTree(ref root_hash) => {
                // roothashset
                let roothash_keyspace = get_roothashset_keyspace(name);
                let value = self
                    .storage
                    .get(roothash_keyspace, hex::encode(&root_hash))?;
                // found
                if value.is_some() {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
    fn get_public_keys(&self, name: &str, _enckey: &SecKey) -> Result<IndexSet<PublicKey>> {
        // pubkey
        let info_keyspace = format!("{}_{}_info", KEYSPACE, name);
        let staking_keyspace = get_stakingkey_keyspace(name);
        let stakingkey_count: u64 =
            read_number(&self.storage, &info_keyspace, "stakingkeyindex", Some(0))?;
        let mut ret: IndexSet<PublicKey> = Default::default();
        for i in 0..stakingkey_count {
            let public_key = read_pubkey(&self.storage, &staking_keyspace, &format!("{}", i))?;
            ret.insert(public_key);
        }
        Ok(ret)
    }
    fn get_roothashes(&self, name: &str, _enckey: &SecKey) -> Result<IndexSet<H256>> {
        // roothash
        let info_keyspace = format!("{}_{}_info", KEYSPACE, name);
        let roothash_keyspace = get_roothash_keyspace(name);
        let roothash_count: u64 =
            read_number(&self.storage, &info_keyspace, "roothashindex", Some(0))?;
        let mut ret: IndexSet<H256> = Default::default();

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
}
/// Wallet meta data
#[derive(Clone)]
pub struct Wallet {
    /// storage
    pub wallet_storage: Option<Arc<Mutex<dyn WalletStorage>>>,
    /// name of the wallet
    pub name: String,
    /// enckey for the wallet
    pub enckey: Option<SecKey>,
    /// view key to decrypt enclave transactions
    pub view_key: PublicKey,
    /// wallet type
    pub wallet_kind: WalletKind,
}

impl Encode for Wallet {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.view_key.encode_to(dest);
        self.wallet_kind.encode_to(dest);
    }
}

impl Decode for Wallet {
    fn decode<I: Input>(input: &mut I) -> std::result::Result<Self, parity_scale_codec::Error> {
        let view_key = PublicKey::decode(input)?;
        let wallet_kind = WalletKind::decode(input)?;
        Ok(Wallet {
            wallet_storage: None,
            name: "".into(),
            enckey: None,
            view_key,
            wallet_kind,
        })
    }
}

impl Wallet {
    /// Creates a new instance of `Wallet`
    pub fn new(
        view_key: PublicKey,
        wallet_kind: WalletKind,
        name: &str,
        enckey: Option<SecKey>,
    ) -> Self {
        Self {
            wallet_storage: None,
            name: name.into(),
            enckey,
            view_key,
            wallet_kind,
        }
    }

    // detect wallet error
    fn check_wallet(&self) -> Result<()> {
        if self.wallet_storage.is_none() {
            return Err(Error::new(ErrorKind::InvalidInput, "no wallet-storage"));
        }
        if self.enckey.is_none() {
            return Err(Error::new(ErrorKind::InvalidInput, "no enckey"));
        }
        Ok(())
    }

    /// Returns all staking addresses stored in a wallet
    pub fn get_staking_addresses(&self) -> Result<IndexSet<StakedStateAddress>> {
        self.check_wallet()?;
        let storage = self
            .wallet_storage
            .as_ref()
            .expect("as_ref wallet_storage")
            .lock()
            .expect("lock wallet_storage");
        let enckey = &self.enckey.as_ref().expect("enckey wallet_storage");

        let pubkeys = storage
            .get_public_keys(&self.name, enckey)
            .expect("get_staking_addresses");

        Ok(pubkeys
            .iter()
            .map(|public_key| StakedStateAddress::BasicRedeem(RedeemAddress::from(public_key)))
            .collect())
    }

    /// Returns all public-kyes in a wallet
    pub fn get_staking_addresses_publickey(&self) -> Result<IndexSet<PublicKey>> {
        self.check_wallet()?;
        let storage = self
            .wallet_storage
            .as_ref()
            .expect("as_ref wallet_storage")
            .lock()
            .expect("lock wallet_storage");
        let enckey = &self.enckey.as_ref().expect("enckey wallet_storage");
        storage.get_public_keys(&self.name, enckey)
    }

    /// Returns all tree addresses stored in a wallet
    pub fn get_transfer_addresses(&self) -> Result<IndexSet<ExtendedAddr>> {
        self.check_wallet()?;
        let storage = self
            .wallet_storage
            .as_ref()
            .expect("as_ref wallet_storage")
            .lock()
            .expect("lock wallet_storage");
        let enckey = &self.enckey.as_ref().expect("enckey wallet_storage");

        let roothashes = storage
            .get_roothashes(&self.name, enckey)
            .expect("get_transfer_addresses");

        Ok(roothashes
            .iter()
            .cloned()
            .map(ExtendedAddr::OrTree)
            .collect())
    }

    /// Returns all tree addresses stored in a wallet
    pub fn get_transfer_addresses_roothash(&self) -> Result<IndexSet<H256>> {
        self.check_wallet()?;
        let storage = self
            .wallet_storage
            .as_ref()
            .expect("as_ref wallet_storage")
            .lock()
            .expect("lock wallet_storage");
        let enckey = &self.enckey.as_ref().expect("enckey wallet_storage");
        storage.get_roothashes(&self.name, enckey)
    }

    /// this address belongs to this wallet?
    pub fn staking_addresses_contains(&self, addr: &StakedStateAddress) -> Result<bool> {
        self.check_wallet()?;
        let storage = self
            .wallet_storage
            .as_ref()
            .expect("as_ref wallet_storage")
            .lock()
            .expect("lock wallet_storage");
        let enckey = &self.enckey.as_ref().expect("enckey wallet_storage");
        storage.staking_addresses_contains(&self.name, enckey, addr)
    }

    /// this address belongs to this wallet?
    pub fn transfer_addresses_contains(&self, addr: &ExtendedAddr) -> Result<bool> {
        self.check_wallet()?;
        let storage = self
            .wallet_storage
            .as_ref()
            .expect("as_ref wallet_storage")
            .lock()
            .expect("lock wallet_storage");
        let enckey = &self.enckey.as_ref().expect("enckey wallet_storage");
        storage.transfer_addresses_contains(&self.name, enckey, addr)
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

/// Load wallet info from storage
pub fn load_wallet_info<S: SecureStorage>(
    storage: &S,
    name: &str,
    enckey: &SecKey,
) -> Result<Option<Wallet>> {
    let wallet: Option<Wallet> = storage.load_secure(KEYSPACE, name, enckey)?;
    Ok(wallet)
}

/// Load wallet from storage
pub fn load_wallet<S: SecureStorage + 'static>(
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
        // load walletkind
        let walletkind: u64 = read_number(storage, &info_keyspace, "walletkind", Some(0))?;
        new_wallet.wallet_kind = walletkind.into();
        // set name, enckey
        new_wallet.name = name.into();
        new_wallet.enckey = Some(enckey.clone());
        let newstorage = storage.clone();
        new_wallet.wallet_storage = Some(Arc::new(Mutex::new(WalletStorageImpl::new(newstorage))));

        return Ok(Some(new_wallet));
    }
    Ok(None)
}

fn generate_page(all_items_count: u64, offset: u64, limit: u64, reversed: bool) -> Vec<u64> {
    let ret: Vec<u64>;
    if reversed {
        let start = all_items_count.saturating_sub(offset);
        let mut end = 0;
        if limit > 0 {
            end = start.saturating_sub(limit);
        }
        let mut tmp: Vec<u64> = (end..start).collect();
        tmp.reverse();
        ret = tmp;
    } else {
        let start = offset;
        let mut end = all_items_count;
        if limit > 0 {
            end = std::cmp::min(offset + limit, all_items_count);
        }
        ret = (start..end).collect();
    }
    ret
}

/// Maintains mapping `wallet-name -> wallet-details`
#[derive(Debug, Default, Clone)]
pub struct WalletService<T: Storage> {
    storage: T,
}

impl<T> WalletService<T>
where
    T: Storage + 'static,
{
    /// Creates a new instance of wallet service
    pub fn new(storage: T) -> Self {
        WalletService { storage }
    }

    /// Get the wallet info from storage
    pub fn get_wallet_info(&self, name: &str, enckey: &SecKey) -> Result<Wallet> {
        load_wallet_info(&self.storage, name, enckey)?.err_kind(ErrorKind::InvalidInput, || {
            format!("Wallet with name ({}) not found", name)
        })
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

        // write wallet name
        let wallet_keyspace = get_wallet_keyspace();
        self.storage
            .set(wallet_keyspace, name, name.as_bytes().to_vec())?;

        // wallet kind
        write_number(
            &self.storage,
            &info_keyspace,
            "walletkind",
            wallet.wallet_kind as u64,
        )?;

        // stakingkey
        write_number(&self.storage, &info_keyspace, "publicindex", 0)?;
        write_number(&self.storage, &info_keyspace, "stakingkeyindex", 0)?;
        // root hash
        write_number(&self.storage, &info_keyspace, "roothashindex", 0)?;
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
            Ok(None)
        }
    }

    /// Finds ChainPath corresponding to given public_key
    pub fn find_chain_path(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<Option<ChainPath>> {
        let chain_path_keyspace = get_hdpath_keyspace(name);

        // key: public_key
        // value: ChainPath
        let value = self
            .storage
            .get_secure(chain_path_keyspace, public_key.serialize(), enckey)?;
        if let Some(raw) = value {
            let chain_path = ChainPath::decode(raw).map_err(|_| ErrorKind::DeserializationError)?;
            Ok(Some(chain_path))
        } else {
            Ok(None)
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
            Ok(None)
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

        Ok(None)
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

        let newstorage = self.storage.clone();
        let mut newone = Wallet::new(view_key, wallet_kind, name, Some(enckey.clone()));
        newone.wallet_storage = Some(Arc::new(Mutex::new(WalletStorageImpl::new(newstorage))));
        self.set_wallet(name, enckey, newone)?;

        Ok(())
    }

    /// Returns view key of wallet
    pub fn view_key(&self, name: &str, enckey: &SecKey) -> Result<PublicKey> {
        let _wallet_found = self.get_wallet_info(name, enckey)?;
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

        let _wallet_found = self.get_wallet_info(name, enckey)?;

        let public_keyspace = get_public_keyspace(name);

        let mut ret: IndexSet<PublicKey> = IndexSet::<PublicKey>::new();
        let info_keyspace = get_info_keyspace(name);
        let publickey_count: u64 = read_number(&self.storage, &info_keyspace, "publicindex", None)?;

        for i in 0..publickey_count {
            let pubkey = read_pubkey(&self.storage, &public_keyspace, &format!("{}", i))?;
            ret.insert(pubkey);
        }
        Ok(ret)
    }

    /// Returns all public keys corresponding to staking addresses stored in a wallet
    pub fn staking_keys(
        &self,
        name: &str,
        enckey: &SecKey,
        offset: u64,
        limit: u64,
        reversed: bool,
    ) -> Result<IndexSet<PublicKey>> {
        if !self.storage.contains_key(KEYSPACE, name)? {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Wallet with name ({}) not found", name),
            ));
        }
        let _wallet_found = self.get_wallet_info(name, enckey)?;
        let stakingkey_keyspace = get_stakingkey_keyspace(name);
        let mut ret: IndexSet<PublicKey> = IndexSet::<PublicKey>::new();
        let info_keyspace = get_info_keyspace(name);
        let staking_count: u64 =
            read_number(&self.storage, &info_keyspace, "stakingkeyindex", None)?;

        let items = generate_page(staking_count, offset, limit, reversed);
        for i in items {
            let pubkey = read_pubkey(&self.storage, &stakingkey_keyspace, &format!("{}", i))?;
            ret.insert(pubkey);
        }
        Ok(ret)
    }

    /// Returns all staking addresses stored in a wallet
    pub fn staking_addresses(
        &self,
        name: &str,
        enckey: &SecKey,
        offset: u64,
        limit: u64,
        reversed: bool,
    ) -> Result<IndexSet<StakedStateAddress>> {
        let pubkeys: IndexSet<PublicKey> =
            self.staking_keys(name, enckey, offset, limit, reversed)?;
        let mut ret: IndexSet<StakedStateAddress> = IndexSet::<StakedStateAddress>::new();
        for pubkey in &pubkeys {
            let staked = StakedStateAddress::BasicRedeem(RedeemAddress::from(pubkey));
            ret.insert(staked);
        }
        Ok(ret)
    }

    /// Returns all multi-sig addresses stored in a wallet
    pub fn root_hashes(
        &self,
        name: &str,
        enckey: &SecKey,
        offset: u64,
        limit: u64,
        reversed: bool,
    ) -> Result<IndexSet<H256>> {
        if !self.storage.contains_key(KEYSPACE, name)? {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Wallet with name ({}) not found", name),
            ));
        }
        let _wallet_found = self.get_wallet_info(name, enckey)?;
        let roothash_keyspace = get_roothash_keyspace(name);
        let mut ret: IndexSet<H256> = IndexSet::<H256>::new();
        let info_keyspace = get_info_keyspace(name);
        let roothash_count: u64 =
            read_number(&self.storage, &info_keyspace, "roothashindex", None)?;

        let items = generate_page(roothash_count, offset, limit, reversed);
        for i in items {
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
        offset: u64,
        limit: u64,
        reversed: bool,
    ) -> Result<IndexSet<ExtendedAddr>> {
        let roothashes: IndexSet<H256> = self.root_hashes(name, enckey, offset, limit, reversed)?;
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

    /// Adds a (public_key, hd_path) pair to given wallet
    pub fn add_key_path(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
        hd_path: &ChainPath,
    ) -> Result<()> {
        let hdpath_keyspace = get_hdpath_keyspace(name);
        self.storage.set_secure(
            hdpath_keyspace,
            public_key.serialize(),
            hd_path.clone().encode(),
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
            &format!("{}", index_value),
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
            &format!("{}", index_value),
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
        let wallet_found = self.get_wallet_info(name, enckey)?;
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_wallet_info_serialize() {
        let public_key_1 = PublicKey::from(&PrivateKey::new().unwrap());
        let public_key_2 = PublicKey::from(&PrivateKey::new().unwrap());
        let public_key_3 = PublicKey::from(&PrivateKey::new().unwrap());
        let private_key = PrivateKey::new().unwrap();
        let wallet = Wallet {
            wallet_storage: None,
            name: "".into(),
            enckey: None,
            view_key: PublicKey::from(&private_key),
            wallet_kind: WalletKind::Basic,
        };
        let wallet_raw = wallet.encode();
        let wallet_2 = Wallet::decode(&mut wallet_raw.as_slice()).unwrap();
        assert_eq!(wallet_2.wallet_kind, WalletKind::Basic);

        let mut key_pairs = BTreeMap::new();
        key_pairs.insert(public_key_1.clone(), PrivateKey::new().unwrap());
        let mut multisig_address_pair = BTreeMap::new();
        let multisig_address =
            MultiSigAddress::new(vec![public_key_1.clone(), public_key_2], public_key_1, 1)
                .unwrap();
        multisig_address_pair.insert("0".into(), multisig_address);

        let mut key_chainpath = BTreeMap::new();
        key_chainpath.insert(public_key_3, "m/44'/0'/0'/0/{}".into());

        let info = WalletInfo {
            name: "test".into(),
            wallet,
            private_key: PrivateKey::new().unwrap(),
            passphrase: Some("abc".into()),
            key_pairs,
            key_chainpath,
            hdkey: Some(HdKey::default()),
            multisig_address_pair,
            staking_keys: vec![],
        };
        let s = serde_json::to_string(&info);
        assert!(s.is_ok());
    }
}
