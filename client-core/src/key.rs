//! Key management
use bincode::{deserialize, serialize};
use failure::ResultExt;
use rand::rngs::OsRng;
use secp256k1::{PublicKey as SecpPublicKey, SecretKey};

use chain_core::init::address::RedeemAddress;

use crate::SECP;
use crate::{ErrorKind, Result};

/// Private key used in Crypto.com Chain
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    /// Generates a new private key
    pub fn new() -> Result<PrivateKey> {
        let mut rng = OsRng::new().context(ErrorKind::KeyGenerationError)?;
        let secret_key = SecretKey::new(&mut rng);

        Ok(PrivateKey(secret_key))
    }

    /// Serializes current private key
    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(serialize(&self.0).context(ErrorKind::SerializationError)?)
    }

    /// Deserializes private key from bytes
    pub fn deserialize_from(bytes: &[u8]) -> Result<PrivateKey> {
        let secret_key: SecretKey = deserialize(bytes).context(ErrorKind::DeserializationError)?;

        Ok(PrivateKey(secret_key))
    }
}

/// Public key used in Crypto.com Chain
pub struct PublicKey(SecpPublicKey);

impl From<&PrivateKey> for PublicKey {
    fn from(private_key: &PrivateKey) -> Self {
        let secret_key = &private_key.0;

        let public_key = SECP.with(|secp| SecpPublicKey::from_secret_key(secp, secret_key));

        PublicKey(public_key)
    }
}

impl From<&PublicKey> for RedeemAddress {
    fn from(public_key: &PublicKey) -> Self {
        Self::from(&public_key.0)
    }
}
