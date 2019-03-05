use bincode::{deserialize, serialize};
use blake2::{Blake2s, Digest};
use failure::{format_err, Error, ResultExt};
use miscreant::{Aead, Aes128PmacSivAead};
use rand::rngs::OsRng;
use rand::Rng;
use sled::{ConfigBuilder, Db};
use zeroize::Zeroize;

use crate::constants::{SECRETS_STORAGE_PATH, STORAGE_PATH};
use crate::Secrets;

/// Nonce size in bytes
pub const NONCE_SIZE: usize = 8;

pub struct Storage(Db);

impl Storage {
    pub fn new() -> Result<Self, Error> {
        Ok(Self(
            Db::start(
                ConfigBuilder::new()
                    .path(STORAGE_PATH.to_owned() + SECRETS_STORAGE_PATH)
                    .build(),
            )
            .context("Not able to initialize storage")?,
        ))
    }

    pub fn clear(&self) -> Result<(), Error> {
        self.0.clear().context("Unable to clear storage")?;

        Ok(())
    }

    pub fn get(&self, name: &str, passphrase: &str) -> Result<Secrets, Error> {
        let key = serialize(name).context("Unable to serialize key")?;

        match self.0.get(key).context("Unable to connect to storage")? {
            None => Err(format_err!("No address found with name: {}!", name)),
            Some(value) => {
                let nonce_index = value.len() - NONCE_SIZE;

                let mut algo = Self::get_algo(passphrase)?;

                Ok(deserialize(
                    &algo
                        .open(
                            &value[nonce_index..],
                            name.as_bytes(),
                            &value[..nonce_index],
                        )
                        .context("Unable to decrypt secrets")?,
                )
                .context("Unable to deserialize secrets")?)
            }
        }
    }

    pub fn set(&self, name: &str, secrets: &Secrets, passphrase: &str) -> Result<(), Error> {
        if self
            .0
            .contains_key(name)
            .context("Unable to connect to storage")?
        {
            Err(format_err!("Address with name: {} already exists", name))
        } else {
            let mut algo = Self::get_algo(passphrase)?;

            let mut nonce = [0u8; NONCE_SIZE];
            let mut rand = OsRng::new()?;
            rand.fill(&mut nonce);

            let mut cipher = algo.seal(
                &nonce,
                name.as_bytes(),
                &serialize(&secrets).context("Unable to serialize secrets")?,
            );
            cipher.extend(&nonce[..]);

            self.0
                .set(serialize(name).context("Unable to serialize name")?, cipher)
                .context("Unable to store secrets")?;
            Ok(())
        }
    }

    pub fn list_keys(&self) -> Result<Vec<String>, Error> {
        let keys = self.0.iter().keys();

        keys.map(|key| -> Result<String, Error> {
            Ok(deserialize(&key.context("Pagecache error")?)
                .context("Unable to deserialize key")?)
        })
        .collect()
    }

    /// Returns the encryptor/decryptor for passphrase entered by user
    fn get_algo(passphrase: &str) -> Result<Aes128PmacSivAead, Error> {
        let mut hasher = Blake2s::new();
        hasher.input(passphrase);

        let mut passphrase = hasher.result_reset();

        let algo = Aes128PmacSivAead::new(&passphrase);

        passphrase.zeroize();

        Ok(algo)
    }
}
