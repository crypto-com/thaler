use bincode::{deserialize, serialize};
use failure::ResultExt;

use crate::{ErrorKind, PrivateKey, Result, SecureStorage};

/// Exposes functionality for managing public and private keys
#[derive(Default)]
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

#[cfg(test)]
mod tests {
    use super::KeyService;
    use crate::storage::SledStorage;
    use crate::ErrorKind;

    #[test]
    fn check_flow() {
        let key_service = KeyService::new(
            SledStorage::new("./key-service-test").expect("Unable to create key sled storage"),
        );

        let private_key = key_service
            .generate("wallet_id", "passphrase")
            .expect("Unable to generate private key");

        let new_private_key = key_service
            .generate("wallet_id", "passphrase")
            .expect("Unable to generate private key");

        let keys = key_service
            .get_keys("wallet_id", "passphrase")
            .expect("Unable to get keys from storage")
            .expect("No keys found");

        assert_eq!(2, keys.len(), "Unexpected key length");
        assert_eq!(private_key, keys[0], "Invalid private key found");
        assert_eq!(new_private_key, keys[1], "Invalid private key found");

        let error = key_service
            .get_keys("wallet_id", "incorrect_passphrase")
            .expect_err("Decryption worked with incorrect passphrase");

        assert_eq!(
            error.kind(),
            ErrorKind::DecryptionError,
            "Invalid error kind"
        );
    }
}
