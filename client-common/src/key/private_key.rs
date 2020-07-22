use crate::Transaction;
use chain_core::tx::TransactionId;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use rand::rngs::OsRng;
use secp256k1::schnorrsig::{schnorr_sign, schnorr_sign_aux, AuxRandNonce, SchnorrSignature};
use secp256k1::{recovery::RecoverableSignature, Message, PublicKey as SecpPublicKey, SecretKey};
use std::convert::TryInto;
use zeroize::Zeroize;

use crate::{ErrorKind, PublicKey, Result, ResultExt, SECP};

/// a object acts like a private key should impl the trait
pub trait PrivateKeyAction: Sync + Send {
    /// Signs a message with current private key
    fn sign(&self, tx: &Transaction) -> Result<RecoverableSignature>;

    /// Signs a message with current private key (uses schnorr signature algorithm)
    fn schnorr_sign(&self, tx: &Transaction) -> Result<SchnorrSignature>;

    /// Signs a message with current private key (uses schnorr aux signature algorithm), used in dev-utils only
    fn schnorr_sign_unsafe(&self, tx: &Transaction, aux_payload: &[u8])
        -> Result<SchnorrSignature>;

    /// Signs a message with current private key
    fn public_key(&self) -> Result<PublicKey>;
}

/// Private key used in Crypto.com Chain
#[derive(Debug, PartialEq, Clone)]
pub struct PrivateKey(SecretKey);

impl PrivateKeyAction for PrivateKey {
    fn sign(&self, tx: &Transaction) -> Result<RecoverableSignature> {
        let tx_id = tx.id();
        let message = Message::from_slice(&tx_id).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize message to sign",
            )
        })?;
        let signature = SECP.with(|secp| secp.sign_recoverable(&message, &self.0));
        Ok(signature)
    }

    fn schnorr_sign(&self, tx: &Transaction) -> Result<SchnorrSignature> {
        let tx_id = tx.id();
        let message = Message::from_slice(&tx_id).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize message to sign",
            )
        })?;
        let signature = SECP.with(|secp| schnorr_sign(&secp, &message, &self.0, &mut OsRng));
        Ok(signature)
    }

    fn schnorr_sign_unsafe(
        &self,
        tx: &Transaction,
        aux_payload: &[u8],
    ) -> Result<SchnorrSignature> {
        let tx_id = tx.id();
        let message = Message::from_slice(&tx_id).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize message to sign",
            )
        })?;
        let aux_payload = aux_payload
            .try_into()
            .chain(|| (ErrorKind::InvalidInput, "invalid aux_payload length"))?;

        let aux_rand = AuxRandNonce::deserialize_from(aux_payload);
        let signature = SECP.with(|secp| schnorr_sign_aux(&secp, &message, &self.0, &aux_rand));
        Ok(signature)
    }

    fn public_key(&self) -> Result<PublicKey> {
        let secret_key = &self.0;

        let public_key = SECP.with(|secp| SecpPublicKey::from_secret_key(secp, secret_key));

        Ok(public_key.into())
    }
}

impl PrivateKey {
    /// Generates a new private key
    pub fn new() -> Result<PrivateKey> {
        let mut rng = OsRng;
        let secret_key = SecretKey::new(&mut rng);

        Ok(PrivateKey(secret_key))
    }

    /// Serializes current private key
    pub fn serialize(&self) -> Vec<u8> {
        self.0[..].to_vec()
    }

    /// Deserializes private key from bytes
    pub fn deserialize_from(bytes: &[u8]) -> Result<PrivateKey> {
        let secret_key: SecretKey = SecretKey::from_slice(bytes).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize secret key",
            )
        })?;

        Ok(PrivateKey(secret_key))
    }
}

impl Encode for PrivateKey {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.serialize().encode_to(dest)
    }

    fn size_hint(&self) -> usize {
        33
    }
}

impl Decode for PrivateKey {
    fn decode<I: Input>(input: &mut I) -> std::result::Result<Self, Error> {
        let serialized = <Vec<u8>>::decode(input)?;
        PrivateKey::deserialize_from(&serialized)
            .map_err(|_| Error::from("Unable to decode private key"))
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(private_key: &PrivateKey) -> Self {
        private_key.public_key().unwrap()
    }
}

impl From<&PrivateKey> for SecretKey {
    fn from(private_key: &PrivateKey) -> Self {
        private_key.0
    }
}

impl From<SecretKey> for PrivateKey {
    fn from(secret_key: SecretKey) -> Self {
        Self(secret_key)
    }
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.zeroize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_serialization() {
        // Hex representation: "c553a03604235df8fcd14fc6d1e5b18a219fbcc6e93effcfcf768e2977a74ec2"
        let secret_arr: Vec<u8> = vec![
            197, 83, 160, 54, 4, 35, 93, 248, 252, 209, 79, 198, 209, 229, 177, 138, 33, 159, 188,
            198, 233, 62, 255, 207, 207, 118, 142, 41, 119, 167, 78, 194,
        ];

        let private_key = PrivateKey::deserialize_from(&secret_arr)
            .expect("Unable to deserialize private key from byte array");

        let private_arr = private_key.serialize();

        assert_eq!(
            secret_arr, private_arr,
            "Serialization / Deserialization is implemented incorrectly"
        );
    }

    #[test]
    fn check_rng_serialization() {
        let private_key = PrivateKey::new().expect("Unable to generate private key");

        let private_arr = private_key.serialize();

        let secret_key =
            PrivateKey::deserialize_from(&private_arr).expect("Unable to deserialize private key");

        assert_eq!(
            private_key, secret_key,
            "Serialization / Deserialization is implemented incorrectly"
        );
    }

    #[test]
    fn check_encoding() {
        let private_key = PrivateKey::new().unwrap();
        let new_private_key = PrivateKey::decode(&mut private_key.encode().as_slice()).unwrap();

        assert_eq!(
            private_key, new_private_key,
            "Encoding / Decoding is implemented incorrectly"
        );
    }
}
