//! Zeroized encryption key type
use std::str::FromStr;

use aes::{block_cipher_trait::BlockCipher, Aes256};
use aes_gcm_siv::aead::generic_array::{typenum::Unsigned, GenericArray};
use argon2;
use blake2::{Blake2s, Digest};
use hmac::{Hmac, Mac};
use secstr::{SecBox, SecUtf8};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{Error, ErrorKind, Result};

/// Encryption key size
pub type SecKeySize = <Aes256 as BlockCipher>::KeySize;
/// Encryption key
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
        if bytes.len() != SecKeySize::to_usize() {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid seckey length"));
        }
        let arr = GenericArray::clone_from_slice(&bytes);
        bytes.zeroize();
        Ok(SecKey(SecBox::new(Box::new(arr))))
    } else {
        Err(Error::new(ErrorKind::InvalidInput, "invalid hex seckey"))
    }
}

/// derive encryption key from passphrase
pub fn derive_enckey(passphrase: &SecUtf8, name: &str) -> argon2::Result<SecKey> {
    let salt = Blake2s::digest(name.as_bytes());
    let mut extended =
        argon2::hash_raw(passphrase.unsecure().as_bytes(), &salt, &Default::default())?;
    let mut mac = Hmac::<Sha256>::new_varkey(&extended).unwrap();
    extended.zeroize();
    mac.input(b"Wallet Data Encryption");
    let arr = mac.result_reset().code();
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
