//! Data storage layer
#[cfg(any(test, feature = "hash-map"))]
mod hash_map_storage;
#[cfg(all(not(test), feature = "sled"))]
mod sled_storage;

#[cfg(any(test, feature = "hash-map"))]
pub use hash_map_storage::HashMapStorage;
#[cfg(all(not(test), feature = "sled"))]
pub use sled_storage::SledStorage;

use blake2::{Blake2s, Digest};
use failure::ResultExt;
use miscreant::{Aead, Aes128PmacSivAead};
use rand::rngs::OsRng;
use rand::Rng;

use crate::{ErrorKind, Result};

/// Nonce size in bytes
const NONCE_SIZE: usize = 8;

/// Interface for a generic key-value storage
pub trait Storage: Send + Sync {
    /// Clears all data in storage.
    fn clear(&self) -> Result<()>;

    /// Returns value of key if it exists.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Set a key to a new value, returning old value if it was set.
    fn set(&self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>>;

    /// Returns a vector of stored keys
    fn keys(&self) -> Result<Vec<Vec<u8>>>;

    /// Returns `true` if the storage contains a value for the specified key, `false` otherwise.
    fn contains_key(&self, key: &[u8]) -> Result<bool>;
}

/// Interface for a generic key-value storage (with encryption)
pub trait SecureStorage {
    /// Returns value (after decryption) of key if it exists.
    fn get_secure(&self, key: &[u8], passphrase: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Set a key to a new value (after encryption). This function returns [`Error`](crate::Error) of
    /// [`ErrorKind`](crate::ErrorKind): `AlreadyExists` when the specified key is already present in
    /// storage.
    fn set_secure(&self, key: &[u8], value: Vec<u8>, passphrase: &[u8]) -> Result<Option<Vec<u8>>>;
}

impl<T> SecureStorage for T
where
    T: Storage,
{
    fn get_secure(&self, key: &[u8], passphrase: &[u8]) -> Result<Option<Vec<u8>>> {
        let value = self.get(key)?;

        match value {
            None => Ok(None),
            Some(inner) => {
                let nonce_index = inner.len() - NONCE_SIZE;
                let mut algo = get_algo(passphrase);

                Ok(Some(
                    algo.open(&inner[nonce_index..], key, &inner[..nonce_index])
                        .context(ErrorKind::DecryptionError)?,
                ))
            }
        }
    }

    fn set_secure(&self, key: &[u8], value: Vec<u8>, passphrase: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut algo = get_algo(passphrase);

        let mut nonce = [0u8; NONCE_SIZE];
        let mut rand = OsRng::new().context(ErrorKind::RngError)?;
        rand.fill(&mut nonce);

        let mut cipher = algo.seal(&nonce, key, &value);
        cipher.extend(&nonce[..]);

        self.set(key, cipher)
    }
}

fn get_algo(passphrase: &[u8]) -> Aes128PmacSivAead {
    let mut hasher = Blake2s::new();
    hasher.input(passphrase);

    Aes128PmacSivAead::new(&hasher.result_reset())
}
