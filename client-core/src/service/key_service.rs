use secstr::SecUtf8;
use zeroize::Zeroize;

use client_common::Result;
use client_common::{PrivateKey, PublicKey, SecureStorage, Storage};

const KEYSPACE: &str = "core_key";

/// Maintains mapping `public-key -> private-key`
#[derive(Debug, Default, Clone)]
pub struct KeyService<T: SecureStorage> {
    storage: T,
}

impl<T> KeyService<T>
where
    T: Storage,
{
    /// Creates a new instance of key service
    #[inline]
    pub fn new(storage: T) -> Self {
        KeyService { storage }
    }

    /// Adds a new public-private keypair to storage
    pub fn add_keypair(
        &self,
        private_key: &PrivateKey,
        public_key: &PublicKey,
        passphrase: &SecUtf8,
    ) -> Result<()> {
        self.storage
            .set_secure(
                KEYSPACE,
                public_key.serialize(),
                private_key.serialize(),
                passphrase,
            )
            .map(|_| ())
    }

    /// Retrieves private key corresponding to given public key
    pub fn private_key(
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
    #[inline]
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
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

        let private_key = PrivateKey::new().unwrap();
        let public_key = PublicKey::from(&private_key);

        key_service
            .add_keypair(&private_key, &public_key, &passphrase)
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
