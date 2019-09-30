use secstr::SecUtf8;
use zeroize::Zeroize;

use client_common::{PrivateKey, PublicKey, Result, SecureStorage, Storage};

const KEYSPACE: &str = "core_key";

use super::key_service_data::KeyServiceInterface;

/// Maintains mapping `public-key -> private-key`
#[derive(Debug, Default, Clone)]
pub struct SimpleKeyService<T: Storage> {
    storage: T,
}

impl<T> KeyServiceInterface for SimpleKeyService<T>
where
    T: Storage,
{
    /// Generates a new public-private keypair
    fn generate_keypair(
        &self,
        _name: &str,
        passphrase: &SecUtf8,
        _is_staking: bool,
    ) -> Result<(PublicKey, PrivateKey)> {
        let private_key = PrivateKey::new()?;
        let public_key = PublicKey::from(&private_key);

        self.storage.set_secure(
            KEYSPACE,
            public_key.serialize(),
            private_key.serialize(),
            passphrase,
        )?;

        Ok((public_key, private_key))
    }

    /// Retrieves private key corresponding to given public key
    fn private_key(
        &self,
        public_key: &PublicKey,
        passphrase: &SecUtf8,
    ) -> Result<Option<PrivateKey>> {
        let private_key_bytes =
            self.storage
                .get_secure(KEYSPACE, public_key.serialize(), passphrase)?;

        private_key_bytes
            .map(|mut private_key_bytes| {
                let private_key = PrivateKey::deserialize_from(&private_key_bytes)?;
                private_key_bytes.zeroize();
                Ok(private_key)
            })
            .transpose()
    }

    /// Clears all storage
    fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}

impl<T> SimpleKeyService<T>
where
    T: Storage,
{
    /// Creates a new instance of key service
    pub fn new(storage: T) -> Self {
        SimpleKeyService { storage }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use client_common::storage::MemoryStorage;
    use client_common::ErrorKind;

    #[test]
    fn check_flow() {
        let key_service = KeyService::new(MemoryStorage::default());
        let passphrase = SecUtf8::from("passphrase");

        let (public_key, private_key) = key_service
            .generate_keypair(&passphrase)
            .expect("Unable to generate private key");

        let retrieved_private_key = key_service
            .private_key(&public_key, &passphrase)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, retrieved_private_key);

        let error = key_service
            .private_key(&public_key, &SecUtf8::from("incorrect_passphrase"))
            .expect_err("Decryption worked with incorrect passphrase");

        assert_eq!(
            error.kind(),
            ErrorKind::DecryptionError,
            "Invalid error kind"
        );

        assert!(key_service.clear().is_ok());
    }
}
