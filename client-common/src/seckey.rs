//! Zeroized encryption key type
use std::str::FromStr;

use aes::{Aes256, NewBlockCipher};
use aes_gcm_siv::aead::generic_array::GenericArray;
use secstr::{SecBox, SecUtf8};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::{Error, ErrorKind, Result};

/// Encryption key size
pub type SecKeySize = <Aes256 as NewBlockCipher>::KeySize;
/// Encryption key
/// FIXME: generic capability parameter -- https://en.wikipedia.org/wiki/Capability-based_security
/// ref for Rust: https://web.archive.org/web/20180129173236/http://zsck.co/writing/capability-based-apis.html
/// APIs that need the key could then require what capability they need -- e.g. SecKey<View>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecKey(SecBox<GenericArray<u8, SecKeySize>>);

impl SecKey {
    /// imuutable reference to the bytes inside
    pub fn unsecure(&self) -> &GenericArray<u8, SecKeySize> {
        self.0.unsecure()
    }
}

impl FromStr for SecKey {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        parse_hex_enckey(s).map_err(|err| err.to_string())
    }
}

/// Parse encryption key from hex string
pub fn parse_hex_enckey(s: &str) -> Result<SecKey> {
    if let Ok(mut bytes) = hex::decode(s) {
        let arr = GenericArray::from_exact_iter(bytes.iter().copied())
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid seckey length"))?;
        bytes.zeroize();
        Ok(SecKey(SecBox::new(Box::new(arr))))
    } else {
        Err(Error::new(ErrorKind::InvalidInput, "invalid hex seckey"))
    }
}

const GLOBAL_DATA_CONTEXT: &str =
    "Crypto.com Chain Wallet 2020-03-30 16:59:10 global wallet data encryption";
const SALT_CONTEXT: &str = "Crypto.com Chain Wallet 2020-03-30 16:59:10 salt from wallet name";

/// derive encryption key from passphrase
/// FIXME: derivation should derive multiple keys, e.g. for view/sync and spending operations
pub fn derive_enckey(passphrase: &SecUtf8, name: &str) -> argon2::Result<SecKey> {
    let mut salt = [0; 32];
    blake3::derive_key(SALT_CONTEXT, name.as_bytes(), &mut salt);
    let mut extended =
        argon2::hash_raw(passphrase.unsecure().as_bytes(), &salt, &Default::default())?;
    let mut arr = GenericArray::clone_from_slice(&[0; 32]);
    blake3::derive_key(GLOBAL_DATA_CONTEXT, &extended, &mut arr);
    extended.zeroize();
    Ok(SecKey(SecBox::new(Box::new(arr))))
}

impl<'de> Deserialize<'de> for SecKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(|err| D::Error::custom(format!("parse enckey: {}", err)))
    }
}

impl Serialize for SecKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0.unsecure()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;
    use serde_json;

    #[test]
    fn check_enckey_different_for_name() {
        let passphrase = SecUtf8::from("passphrase");
        assert_ne!(
            derive_enckey(&passphrase, "Wallet1"),
            derive_enckey(&passphrase, "Wallet2")
        );
    }

    quickcheck! {
        fn check_serialization(passphrase: String, name: String) -> bool {
            let key = derive_enckey(&SecUtf8::from(passphrase), &name).unwrap();
            SecKey::from_str(&hex::encode(key.unsecure())).unwrap() == key
        }
        fn check_serde_serialization(passphrase: String, name: String) -> bool {
            let key = derive_enckey(&SecUtf8::from(passphrase), &name).unwrap();
            serde_json::from_str::<SecKey>(&serde_json::to_string(&key).unwrap()).unwrap() == key
        }
    }
}
