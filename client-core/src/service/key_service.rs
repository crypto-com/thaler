use bincode::{deserialize, serialize};
use failure::ResultExt;

use crate::{ErrorKind, PrivateKey, Result, SecureStorage};

/// Exposes functionality for managing public and private keys
pub struct KeyService<T> {
    storage: T,
}

impl<T> KeyService<T>
where
    T: SecureStorage,
{
    /// Creates a new instance of key service
    pub fn new(storage: T) -> Self {
        KeyService { storage }
    }

    /// Generates a new address for given wallet ID
    pub fn generate(&self, wallet_id: &str, passphrase: &str) -> Result<PrivateKey> {
        let private_key = PrivateKey::new()?;

        let private_keys = self
            .storage
            .get_secure(wallet_id.as_bytes(), passphrase.as_bytes())?;

        let mut private_keys = match private_keys {
            None => Vec::new(),
            Some(private_keys) => {
                deserialize(&private_keys).context(ErrorKind::DeserializationError)?
            }
        };

        private_keys.push(private_key.serialize()?);

        self.storage.set_secure(
            wallet_id.as_bytes(),
            serialize(&private_keys).context(ErrorKind::SerializationError)?,
            passphrase.as_bytes(),
        )?;

        Ok(private_key)
    }

    /// Returns all the keys stored for given wallet ID
    pub fn get_keys(&self, wallet_id: &str, passphrase: &str) -> Result<Option<Vec<PrivateKey>>> {
        let private_keys = self
            .storage
            .get_secure(wallet_id.as_bytes(), passphrase.as_bytes())?;

        match private_keys {
            None => Ok(None),
            Some(bytes) => {
                let private_keys: Vec<Vec<u8>> =
                    deserialize(&bytes).context(ErrorKind::DeserializationError)?;

                let private_keys = private_keys
                    .iter()
                    .map(|inner| -> Result<PrivateKey> { PrivateKey::deserialize_from(inner) })
                    .collect::<Result<Vec<PrivateKey>>>()?;

                Ok(Some(private_keys))
            }
        }
    }
}
