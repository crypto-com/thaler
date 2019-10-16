use secstr::SecUtf8;
use zeroize::Zeroize;

use crate::hdwallet::traits::Serialize;
use crate::hdwallet::{ChainPath, DefaultKeyChain, ExtendedPrivKey, KeyChain};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use client_common::{Error, ErrorKind, Result};

use client_common::{PrivateKey, PublicKey, SecureStorage, Storage};
const KEYSPACE: &str = "core_key";
const KEYSPACE_HD: &str = "hd_key";
use crate::types::WalletKind;
use chain_core::init::network::get_bip44_coin_type;
use log::debug;

/// get random mnemonic
pub fn get_random_mnemonic() -> Mnemonic {
    Mnemonic::new(MnemonicType::Words24, Language::English)
}

/// Maintains mapping `public-key -> private-key`
#[derive(Debug, Default, Clone)]
pub struct KeyService<T: Storage> {
    storage: T,
}

impl<T> KeyService<T>
where
    T: Storage,
{
    /// Creates a new instance of key service
    pub fn new(storage: T) -> Self {
        KeyService { storage }
    }

    /// Generates keypair by wallet kinds recorded in sled storage
    pub fn generate_keypair_auto(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        is_staking: bool,
    ) -> Result<(PublicKey, PrivateKey)> {
        if self.get_wallet_type(name, passphrase)? == WalletKind::HD {
            self.generate_keypair_hd(name, passphrase, is_staking)
        } else {
            self.generate_keypair_basic(passphrase)
        }
    }

    /// Generates a new public-private keypair
    pub fn generate_keypair_basic(&self, passphrase: &SecUtf8) -> Result<(PublicKey, PrivateKey)> {
        let private_key = PrivateKey::new()?;
        let public_key = PublicKey::from(&private_key);

        self.storage.set_secure(
            KEYSPACE,
            public_key.serialize(),
            private_key.serialize(),
            passphrase,
        )?;

        Ok((public_key, private_key))
    }

    /// Retrieves private key corresponding to given public key
    pub fn private_key(
        &self,
        public_key: &PublicKey,
        passphrase: &SecUtf8,
    ) -> Result<Option<PrivateKey>> {
        let private_key_bytes =
            self.storage
                .get_secure(KEYSPACE, public_key.serialize(), passphrase)?;

        private_key_bytes
            .map(|mut private_key_bytes| {
                let private_key = PrivateKey::deserialize_from(&private_key_bytes)?;
                private_key_bytes.zeroize();
                Ok(private_key)
            })
            .transpose()
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE).expect("clear keyspace");
        self.storage
            .clear(KEYSPACE_HD)
            .expect("clear keyspace for hd");
        Ok(())
    }

    /// get wallet type (hd, basic)
    pub fn get_wallet_type(&self, name: &str, passphrase: &SecUtf8) -> Result<WalletKind> {
        let key = name.as_bytes();
        let value = self.read_value(passphrase, &key[..])?;
        if value.is_some() {
            Ok(WalletKind::HD)
        } else {
            Ok(WalletKind::Basic)
        }
    }
    /// generate seed from mnemonic
    pub fn generate_seed(
        &self,
        mnemonic: &Mnemonic,
        name: &str,
        passphrase: &SecUtf8,
    ) -> Result<()> {
        debug!("hdwallet generate seed={}", mnemonic);
        let seed = Seed::new(&mnemonic, "");
        if self.read_value(passphrase, &name.as_bytes())?.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "hdwallet seed already exists",
            ));
        }
        // key should not exist
        assert!(self.read_value(passphrase, &name.as_bytes())?.is_none());
        assert!(self
            .storage
            .get_secure(KEYSPACE_HD, name, passphrase)
            .is_ok());
        assert!(!self
            .storage
            .get_secure(KEYSPACE_HD, name, passphrase)
            .as_ref()
            .expect("generate_seed get seed")
            .is_some());
        self.storage
            .set_secure(KEYSPACE_HD, name, seed.as_bytes().into(), passphrase)?;
        debug!("hdwallet write seed success");
        Ok(())
    }

    /// read value from db, if it's None, there value doesn't exist
    pub fn read_value(&self, passphrase: &SecUtf8, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .storage
            .get_secure(KEYSPACE_HD, key, passphrase)?
            .clone())
    }

    /// read number, if value doesn't exist, it returns default value
    pub fn read_number(&self, passphrase: &SecUtf8, key: &[u8], default: u32) -> Result<u32> {
        let connected = self.storage.get_secure(KEYSPACE_HD, key, passphrase)?;

        if let Some(value) = connected {
            return Ok(std::str::from_utf8(&value[..])
                .map_err(|_e| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "hdwallet read_number cannot convert from string",
                    )
                })?
                .parse::<u32>()
                .map_err(|_e| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "hdwallet read_number cannot parse from string",
                    )
                })?);
        }
        Ok(default)
    }

    /// write number to store, write number as string
    /// writes hdwallet index, after making a new entry, index increases by 1
    /// so address is generated in deterministic way.
    pub fn write_number(&self, passphrase: &SecUtf8, key: &[u8], value: u32) -> Result<()> {
        let a = value.to_string();
        let b = a.as_bytes();
        self.storage
            .set_secure(KEYSPACE_HD, key, b.to_vec(), passphrase)?;
        Ok(())
    }

    /// m / purpose' / coin_type' / account' / change / address_index
    /// account: donation, savings, common expense
    /// change: 0: external, 1: internal
    /// Generates a new public-private keypair
    pub fn generate_keypair_hd(
        &self,
        name: &str,           // wallet name
        passphrase: &SecUtf8, // wallet pass phrase
        is_staking: bool,     // kind of address
    ) -> Result<(PublicKey, PrivateKey)> {
        let seed_bytes = self.storage.get_secure(KEYSPACE_HD, name, passphrase)?;
        let mut index = if is_staking {
            self.read_number(passphrase, format!("staking_{}", name).as_bytes(), 0)?
        } else {
            self.read_number(passphrase, format!("transfer_{}", name).as_bytes(), 0)?
        };
        debug!("hdwallet index={}", index);
        let cointype = get_bip44_coin_type();
        log::debug!("coin type={}", cointype);
        let account = if is_staking { 1 } else { 0 };

        let chain_path = format!("m/44'/{}'/{}'/0/{}", cointype, account, index);
        let key_chain = DefaultKeyChain::new(
            ExtendedPrivKey::with_seed(&seed_bytes.as_ref().expect("hdwallet get extended")[..])
                .map_err(|_e| Error::new(ErrorKind::InvalidInput, "invalid seed bytes"))?,
        );
        let (key, _derivation) = key_chain
            .derive_private_key(ChainPath::from(chain_path.to_string()))
            .map_err(|_e| Error::new(ErrorKind::InvalidInput, "hdwallet derive private key"))?;
        let mut secret = key.serialize();

        let secret_key_bytes = &mut secret[0..32];
        debug!("hdwallet save index={}", index);
        let private_key = PrivateKey::deserialize_from(&secret_key_bytes)
            .map_err(|_e| Error::new(ErrorKind::InvalidInput, "hdwallet privatekey deserialize"))?;
        secret_key_bytes.zeroize();
        let public_key = PublicKey::from(&private_key);
        self.storage.set_secure(
            KEYSPACE,
            public_key.serialize(),
            private_key.serialize(),
            passphrase,
        )?;
        // done
        index += 1;
        if is_staking {
            self.write_number(passphrase, format!("staking_{}", name).as_bytes(), index)?;
        } else {
            self.write_number(passphrase, format!("transfer_{}", name).as_bytes(), index)?;
        }

        Ok((public_key, private_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use client_common::storage::MemoryStorage;
    use client_common::ErrorKind;

    #[test]
    fn check_flow() {
        let key_service = KeyService::new(MemoryStorage::default());
        let passphrase = SecUtf8::from("passphrase");

        let (public_key, private_key) = key_service
            .generate_keypair_basic(&passphrase)
            .expect("Unable to generate private key");

        let retrieved_private_key = key_service
            .private_key(&public_key, &passphrase)
            .expect("hdwallet check_flow retrieve privatekey")
            .expect("hdwallet check_flow retrieve privatekey2");

        assert_eq!(private_key, retrieved_private_key);

        let error = key_service
            .private_key(&public_key, &SecUtf8::from("incorrect_passphrase"))
            .expect_err("Decryption worked with incorrect passphrase");

        assert_eq!(
            error.kind(),
            ErrorKind::DecryptionError,
            "Invalid error kind"
        );

        assert!(key_service.clear().is_ok());
    }

    #[test]
    fn check_flow_hd() {
        let key_service = KeyService::new(MemoryStorage::default());
        let passphrase = SecUtf8::from("passphrase");
        let name = "testhdwallet";
        let mnemonic =
            Mnemonic::from_phrase("genius pet nothing behave quick movie tragic moon slush unknown educate effort garbage crush topic suspect sausage turkey glare vital clown clog poet flock", Language::English).unwrap();
        assert!(
            key_service
                .get_wallet_type(&name, &passphrase)
                .expect("check_flow_hd get_wallet_type before")
                == WalletKind::Basic
        );
        key_service
            .generate_seed(&mnemonic, name, &passphrase)
            .expect("generate hdwallet seed");
        assert!(
            key_service
                .get_wallet_type(&name, &passphrase)
                .expect("check_flow_hd get_wallet_type after")
                == WalletKind::HD
        );
        let (public_key, private_key) = key_service
            .generate_keypair_hd(name, &passphrase, false)
            .expect("Unable to generate private key");

        // check deterministic of hdwallet
        assert!(
            String::from("03532d8f52237409a83c23fd48bf94a4b008e76ed79c05aa013fa1080dc2d7e8dc")
                == public_key.to_string()
        );
        assert!(
            String::from("66b0a362da2332cb7fdc0c940acf9638f824fe7112d79d7ac7baf341033f8abf")
                == hex::encode(&private_key.serialize())
        );
        {
            let (public_key, private_key) = key_service
                .generate_keypair_hd(name, &passphrase, true)
                .expect("Unable to generate private key");

            // check deterministic of hdwallet
            assert!(
                String::from("02f030e0ae3cec955edb750891f8819b37a7df6a41a1e5d59f93187d0c3d6dcf06")
                    == public_key.to_string()
            );
            assert!(
                String::from("72e1ac47503ec1b814fafda9df402b313a0b7f8d9cca0e30d92e686ca2ed02dd")
                    == hex::encode(&private_key.serialize())
            );
        }
        let retrieved_private_key = key_service
            .private_key(&public_key, &passphrase)
            .expect("hdwallet check_flow retrieve privatekey")
            .expect("hdwallet check_flow retrieve privatekey2");

        assert_eq!(private_key, retrieved_private_key);

        let error = key_service
            .private_key(&public_key, &SecUtf8::from("incorrect_passphrase"))
            .expect_err("Decryption worked with incorrect passphrase");

        assert_eq!(
            error.kind(),
            ErrorKind::DecryptionError,
            "Invalid error kind"
        );

        assert!(key_service.clear().is_ok());
    }

    #[test]
    fn check_read_write_numbers() {
        let key_service = KeyService::new(MemoryStorage::default());
        let passphrase = SecUtf8::from("passphrase");
        let name = "testhdwallet";
        let number = 100;
        assert!(
            key_service
                .read_number(&passphrase, &format!("staking_{}", name).as_bytes(), 0)
                .expect("check_read_write_numbers read_number")
                == 0
        );
        key_service
            .write_number(&passphrase, &format!("staking_{}", name).as_bytes(), number)
            .expect("check_read_write_numbers write_number");
        assert!(
            key_service
                .read_number(&passphrase, &format!("staking_{}", name).as_bytes(), 0)
                .expect("check_read_write_numbers read_number")
                == number
        );

        assert!(
            key_service
                .read_number(&passphrase, &format!("invalid_{}", name).as_bytes(), 0)
                .expect("check_read_write_numbers read_number")
                == 0
        );
    }

    #[test]
    fn check_random_mnemonics() {
        let a = get_random_mnemonic();
        let b = get_random_mnemonic();
        assert!(a.to_string() != String::new());
        assert!(a.to_string() != b.to_string());
    }
}
