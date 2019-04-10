use std::fmt;

use failure::ResultExt;
use secp256k1::PublicKey as SecpPublicKey;

use chain_core::init::address::RedeemAddress;
use client_common::{ErrorKind, Result};

/// Public key used in Crypto.com Chain
#[derive(Debug, PartialEq)]
pub struct PublicKey(SecpPublicKey);

impl PublicKey {
    /// Serializes current public key
    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.0.serialize_uncompressed()[..].to_vec())
    }

    /// Deserializes public key from bytes
    pub fn deserialize_from(bytes: &[u8]) -> Result<PublicKey> {
        let public_key: SecpPublicKey =
            SecpPublicKey::from_slice(bytes).context(ErrorKind::DeserializationError)?;

        Ok(PublicKey(public_key))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
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

#[cfg(test)]
mod tests {
    use hex::decode;

    use chain_core::init::address::RedeemAddress;

    use super::super::PrivateKey;
    use super::PublicKey;

    #[test]
    fn check_serialization() {
        let secret_arr: Vec<u8> = vec![
            197, 83, 160, 54, 4, 35, 93, 248, 252, 209, 79, 198, 209, 229, 177, 138, 33, 159, 188,
            198, 233, 62, 255, 207, 207, 118, 142, 41, 119, 167, 78, 194,
        ];

        let private_key = PrivateKey::deserialize_from(&secret_arr)
            .expect("Unable to deserialize private key from byte array");

        let public_key = PublicKey::from(&private_key);

        let public_arr = public_key
            .serialize()
            .expect("Unable to serialize public key");

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
}
