//! Data storage layer
mod memory_storage;
#[cfg(feature = "sled")]
mod sled_storage;

pub use memory_storage::MemoryStorage;
#[cfg(feature = "sled")]
pub use sled_storage::SledStorage;

use blake2::{Blake2s, Digest};
use failure::ResultExt;
use miscreant::{Aead, Aes128PmacSivAead};
use rand::rngs::OsRng;
use rand::Rng;
use secstr::SecStr;

use crate::{ErrorKind, Result};

/// Nonce size in bytes
const NONCE_SIZE: usize = 8;

/// Interface for a generic key-value storage
pub trait Storage: Send + Sync {
    /// Clears all data in a keyspace.
    fn clear<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<()>;

    /// Returns value of key if it exists in keyspace.
    fn get<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, keyspace: S, key: K) -> Result<Option<Vec<u8>>>;

    /// Set a key to a new value in given keyspace, returning old value if it was set.
    fn set<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>>;

    /// Returns a vector of stored keys in a keyspace.
    fn keys<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<Vec<Vec<u8>>>;

    /// Returns `true` if the storage contains a value for the specified key in given keyspace, `false` otherwise.
    fn contains_key<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, keyspace: S, key: K) -> Result<bool>;

    /// Returns all the keyspaces currently available.
    fn keyspaces(&self) -> Result<Vec<Vec<u8>>>;
}

/// Interface for a generic key-value storage (with encryption)
pub trait SecureStorage {
    /// Returns value (after decryption) of key if it exists in given keyspace.
    fn get_secure<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        passphrase: &SecStr,
    ) -> Result<Option<Vec<u8>>>;

    /// Set a key to a new value (after encryption) in given keyspace and return old value.
    fn set_secure<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        value: Vec<u8>,
        passphrase: &SecStr,
    ) -> Result<Option<Vec<u8>>>;
}

impl<T> SecureStorage for T
where
    T: Storage,
{
    fn get_secure<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        passphrase: &SecStr,
    ) -> Result<Option<Vec<u8>>> {
        let value = self.get(keyspace, &key)?;

        match value {
            None => Ok(None),
            Some(inner) => {
                let nonce_index = inner.len() - NONCE_SIZE;
                let mut algo = get_algo(passphrase);

                Ok(Some(
                    algo.open(&inner[nonce_index..], key.as_ref(), &inner[..nonce_index])
                        .context(ErrorKind::DecryptionError)?,
                ))
            }
        }
    }

    fn set_secure<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        value: Vec<u8>,
        passphrase: &SecStr,
    ) -> Result<Option<Vec<u8>>> {
        let old_value = self.get_secure(&keyspace, &key, passphrase)?;

        let mut algo = get_algo(passphrase);

        let mut nonce = [0u8; NONCE_SIZE];
        let mut rand = OsRng::new().context(ErrorKind::RngError)?;
        rand.fill(&mut nonce);

        let mut cipher = algo.seal(&nonce, key.as_ref(), &value);
        cipher.extend(&nonce[..]);

        self.set(keyspace, key, cipher)?;

        Ok(old_value)
    }
}

fn get_algo(passphrase: &SecStr) -> Aes128PmacSivAead {
    let mut hasher = Blake2s::new();
    hasher.input(passphrase.unsecure());
    Aes128PmacSivAead::new(&hasher.result_reset())
}
