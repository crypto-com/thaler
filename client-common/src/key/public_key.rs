use std::fmt;
use std::str::FromStr;

use failure::ResultExt;
use parity_scale_codec::{Decode, Encode, Error as ScaleError, Input, Output};
use secp256k1::key::pubkey_combine;
use secp256k1::PublicKey as SecpPublicKey;
use serde::de::{Deserialize, Deserializer, Error as SerdeDeError, Visitor};
use serde::ser::{Serialize, Serializer};

use chain_core::common::H256;
use chain_core::init::address::RedeemAddress;
use chain_core::tx::witness::tree::RawPubkey;

use crate::{Error, ErrorKind, Result, SECP};

/// Public key used in Crypto.com Chain
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct PublicKey(SecpPublicKey);

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrVisitor;

        impl<'de> Visitor<'de> for StrVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("public key in hexadecimal string")
            }

            #[inline]
            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: SerdeDeError,
            {
                PublicKey::from_str(value).map_err(|err| E::custom(format!("{}", err)))
            }
        }

        deserializer.deserialize_str(StrVisitor)
    }
}

impl PublicKey {
    /// Serializes current public key
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize_uncompressed()[..].to_vec()
    }

    /// Deserializes public key from bytes
    pub fn deserialize_from(bytes: &[u8]) -> Result<PublicKey> {
        let public_key: SecpPublicKey =
            SecpPublicKey::from_slice(bytes).context(ErrorKind::DeserializationError)?;

        Ok(PublicKey(public_key))
    }

    /// Combines multiple public keys into one and also returns hash of combined public key
    pub fn combine(public_keys: &[Self]) -> Result<(Self, H256)> {
        let (public_key, public_key_hash) = SECP
            .with(|secp| {
                pubkey_combine(
                    secp,
                    &public_keys
                        .iter()
                        .map(|key| key.0.clone())
                        .collect::<Vec<SecpPublicKey>>(),
                )
            })
            .context(ErrorKind::InvalidInput)?;

        Ok((Self(public_key), public_key_hash.serialize()))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<PublicKey> {
        Ok(PublicKey(
            SecpPublicKey::from_str(s).context(ErrorKind::DeserializationError)?,
        ))
    }
}

impl From<SecpPublicKey> for PublicKey {
    fn from(public_key: SecpPublicKey) -> Self {
        PublicKey(public_key)
    }
}

impl From<&PublicKey> for RedeemAddress {
    fn from(public_key: &PublicKey) -> Self {
        Self::from(&public_key.0)
    }
}

impl From<PublicKey> for SecpPublicKey {
    fn from(public_key: PublicKey) -> SecpPublicKey {
        public_key.0
    }
}

impl From<&PublicKey> for SecpPublicKey {
    fn from(public_key: &PublicKey) -> SecpPublicKey {
        public_key.0.clone()
    }
}

impl From<PublicKey> for RawPubkey {
    fn from(public_key: PublicKey) -> RawPubkey {
        RawPubkey::from(SecpPublicKey::from(public_key).serialize())
    }
}

impl From<&PublicKey> for RawPubkey {
    fn from(public_key: &PublicKey) -> RawPubkey {
        RawPubkey::from(SecpPublicKey::from(public_key).serialize())
    }
}

impl Encode for PublicKey {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.serialize().encode_to(dest)
    }

    fn size_hint(&self) -> usize {
        66
    }
}

impl Decode for PublicKey {
    fn decode<I: Input>(input: &mut I) -> std::result::Result<Self, ScaleError> {
        let serialized = <Vec<u8>>::decode(input)?;
        PublicKey::deserialize_from(&serialized)
            .map_err(|_| ScaleError::from("Unable to decode public key"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::decode;

    use crate::PrivateKey;

    #[test]
    fn check_serialization() {
        let secret_arr: Vec<u8> = vec![
            197, 83, 160, 54, 4, 35, 93, 248, 252, 209, 79, 198, 209, 229, 177, 138, 33, 159, 188,
            198, 233, 62, 255, 207, 207, 118, 142, 41, 119, 167, 78, 194,
        ];

        let private_key = PrivateKey::deserialize_from(&secret_arr)
            .expect("Unable to deserialize private key from byte array");

        let public_key = PublicKey::from(&private_key);

        let public_arr = public_key.serialize();

        let public_key_new =
            PublicKey::deserialize_from(&public_arr).expect("Unable to deserialize public key");

        assert_eq!(
            public_key, public_key_new,
            "Serialization / Deserialization is implemented incorrectly"
        );
    }

    #[test]
    fn check_address() {
        let secret_arr = decode("208065a247edbe5df4d86fbdc0171303f23a76961be9f6013850dd2bdc759bbb")
            .expect("Unable to decode hex byte array");

        let private_key = PrivateKey::deserialize_from(&secret_arr)
            .expect("Unable to deserialize private key from byte array");

        let public_key = PublicKey::from(&private_key);
        let address = RedeemAddress::from(&public_key);

        let address = address.to_string();

        assert_eq!(
            "0x0bed7abd61247635c1973eb38474a2516ed1d884", address,
            "Address generation implemented incorrectly"
        );
    }

    #[test]
    fn check_combine() {
        let public_key_1 = PublicKey::from(&PrivateKey::new().unwrap());
        let public_key_2 = PublicKey::from(&PrivateKey::new().unwrap());

        let combination = PublicKey::combine(&[public_key_1.clone(), public_key_2.clone()])
            .unwrap()
            .0;

        let manual_combination = PublicKey::from(SECP.with(|secp| {
            pubkey_combine(secp, &[public_key_1.into(), public_key_2.into()])
                .unwrap()
                .0
        }));

        assert_eq!(manual_combination, combination);
    }

    #[test]
    fn check_encoding() {
        let secret_arr: Vec<u8> = vec![
            197, 83, 160, 54, 4, 35, 93, 248, 252, 209, 79, 198, 209, 229, 177, 138, 33, 159, 188,
            198, 233, 62, 255, 207, 207, 118, 142, 41, 119, 167, 78, 194,
        ];

        let private_key = PrivateKey::deserialize_from(&secret_arr)
            .expect("Unable to deserialize private key from byte array");

        let public_key = PublicKey::from(&private_key);

        let public_arr = public_key.encode();

        let public_key_new =
            PublicKey::decode(&mut public_arr.as_slice()).expect("Unable to decode public key");

        assert_eq!(
            public_key, public_key_new,
            "Encoding / Decoding is implemented incorrectly"
        );
    }
}
