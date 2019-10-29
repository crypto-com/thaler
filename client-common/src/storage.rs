//! Data storage layer
mod memory_storage;
#[cfg(feature = "sled")]
mod sled_storage;
mod unauthorized_storage;

pub use memory_storage::MemoryStorage;
#[cfg(feature = "sled")]
pub use sled_storage::SledStorage;
pub use unauthorized_storage::UnauthorizedStorage;

use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use argon2::{self, Config};
use rand::rngs::OsRng;
use rand::Rng;
use secstr::SecUtf8;

use crate::{Error, ErrorKind, Result, ResultExt};

/// Nonce size in bytes
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 8;

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

    /// Delete a key from keyspace
    fn delete<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
    ) -> Result<Option<Vec<u8>>>;

    /// Fetches a value, applies a function and returns the previous value.
    fn fetch_and_update<S, K, F>(&self, keyspace: S, key: K, f: F) -> Result<Option<Vec<u8>>>
    where
        S: AsRef<[u8]>,
        K: AsRef<[u8]>,
        F: Fn(Option<&[u8]>) -> Result<Option<Vec<u8>>>;

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
        passphrase: &SecUtf8,
    ) -> Result<Option<Vec<u8>>>;

    /// Set a key to a new value (after encryption) in given keyspace and return old value.
    fn set_secure<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        value: Vec<u8>,
        passphrase: &SecUtf8,
    ) -> Result<Option<Vec<u8>>>;

    /// Fetches a value, applies a function (after decryption) and returns the previous value.
    fn fetch_and_update_secure<S, K, F>(
        &self,
        keyspace: S,
        key: K,
        passphrase: &SecUtf8,
        f: F,
    ) -> Result<Option<Vec<u8>>>
    where
        S: AsRef<[u8]>,
        K: AsRef<[u8]>,
        F: Fn(Option<&[u8]>) -> Result<Option<Vec<u8>>>;
}

impl<T> SecureStorage for T
where
    T: Storage,
{
    fn get_secure<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        passphrase: &SecUtf8,
    ) -> Result<Option<Vec<u8>>> {
        self.get(keyspace, &key)?
            .map(|value| decrypt_bytes(passphrase, value.as_ref()))
            .transpose()
    }

    fn set_secure<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        value: Vec<u8>,
        passphrase: &SecUtf8,
    ) -> Result<Option<Vec<u8>>> {
        let old_value = self.get_secure(&keyspace, &key, passphrase)?;
        let cipher = encrypt_bytes(passphrase, value)?;
        self.set(keyspace, key, cipher)?;
        Ok(old_value)
    }

    fn fetch_and_update_secure<S, K, F>(
        &self,
        keyspace: S,
        key: K,
        passphrase: &SecUtf8,
        f: F,
    ) -> Result<Option<Vec<u8>>>
    where
        S: AsRef<[u8]>,
        K: AsRef<[u8]>,
        F: Fn(Option<&[u8]>) -> Result<Option<Vec<u8>>>,
    {
        self.fetch_and_update(keyspace, &key, |current| {
            let opened = current
                .map(|current| decrypt_bytes(passphrase, current))
                .transpose()?;

            let next = f(opened.as_ref().map(AsRef::as_ref))?;

            next.map(|next| encrypt_bytes(passphrase, next)).transpose()
        })
    }
}

type Algo = Aes256GcmSiv;

/// returns the encryption/decryption algorithm
pub fn get_algo(passphrase: &SecUtf8, salt: &[u8]) -> Result<Algo> {
    let passphrase_raw = passphrase.unsecure().as_bytes();
    let mut config = Config::default();
    config.hash_length = 32;
    config.time_cost = 1;
    let hash = argon2::hash_raw(passphrase_raw, salt, &config)
        .chain(|| (ErrorKind::HashError, "create passphrase hash error"))?;
    Ok(Aes256GcmSiv::new(GenericArray::clone_from_slice(
        hash.as_ref(),
    )))
}

/// Decrypts bytes with given passphrase and return the decrypted result
pub fn decrypt_bytes(passphrase: &SecUtf8, bytes: &[u8]) -> Result<Vec<u8>> {
    let nonce_index = bytes.len() - (NONCE_SIZE + SALT_SIZE);
    let salt_index = bytes.len() - SALT_SIZE;
    let nonce = bytes[nonce_index..salt_index].as_ref();
    let salt = bytes[salt_index..].as_ref();
    let algo = get_algo(passphrase, salt)?;
    algo.decrypt(
        &GenericArray::clone_from_slice(&nonce),
        bytes[..nonce_index].as_ref(),
    )
    .map_err(|_e| {
        Error::new(
            ErrorKind::DecryptionError,
            "Incorrect passphrase: Unable to unlock stored values",
        )
    })
}

/// Encrypts bytes with given passphrase and return the encrypted result
pub fn encrypt_bytes(passphrase: &SecUtf8, bytes: Vec<u8>) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_SIZE];
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill(&mut nonce);
    OsRng.fill(&mut salt);
    let algo = get_algo(passphrase, &salt)?;
    let mut cipher: Vec<u8> = algo
        .encrypt(
            &GenericArray::clone_from_slice(&nonce),
            bytes.as_slice().as_ref(),
        )
        .map_err(|_e| Error::new(ErrorKind::EncryptionError, "encrypt error"))?;
    cipher.extend(&nonce[..]);
    cipher.extend(&salt[..]);
    Ok(cipher)
}
