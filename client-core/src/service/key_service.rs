use zeroize::Zeroize;

use client_common::Result;
use client_common::{ErrorKind, PrivateKey, PublicKey, ResultExt, SecKey, SecureStorage, Storage};

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
        enckey: &SecKey,
    ) -> Result<()> {
        self.storage
            .set_secure(
                KEYSPACE,
                public_key.serialize(),
                private_key.serialize(),
                enckey,
            )
            .map(|_| ())
    }

    /// Retrieves private key corresponding to given public key
    pub fn private_key(
        &self,
        public_key: &PublicKey,
        enckey: &SecKey,
    ) -> Result<Option<PrivateKey>> {
        let private_key_bytes =
            self.storage
                .get_secure(KEYSPACE, public_key.serialize(), enckey)?;

        private_key_bytes
            .map(|mut private_key_bytes| {
                let private_key = PrivateKey::deserialize_from(&private_key_bytes)?;
                private_key_bytes.zeroize();
                Ok(private_key)
            })
            .transpose()
    }

    /// Delete key pair
    pub fn delete_key(&self, public_key: &PublicKey, enckey: &SecKey) -> Result<()> {
        let serialized = public_key.serialize();
        self.storage
            .get_secure(KEYSPACE, &serialized, enckey)?
            .err_kind(ErrorKind::InvalidInput, || "public key not found")?;
        self.storage.delete(KEYSPACE, &serialized)?;
        Ok(())
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
    use secstr::SecUtf8;

    use client_common::storage::MemoryStorage;
    use client_common::{seckey::derive_enckey, ErrorKind};

    #[test]
    fn check_flow() {
        let key_service = KeyService::new(MemoryStorage::default());
        let enckey = derive_enckey(&SecUtf8::from("passphrase"), "").unwrap();
        let incorrect_enckey = derive_enckey(&SecUtf8::from("passphrase1"), "").unwrap();

        let private_key = PrivateKey::new().unwrap();
        let public_key = PublicKey::from(&private_key);

        key_service
            .add_keypair(&private_key, &public_key, &enckey)
            .expect("Unable to generate private key");

        let retrieved_private_key = key_service
            .private_key(&public_key, &enckey)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, retrieved_private_key);

        let error = key_service
            .private_key(&public_key, &incorrect_enckey)
            .expect_err("Decryption worked with incorrect enckey");

        assert_eq!(
            error.kind(),
            ErrorKind::DecryptionError,
            "Invalid error kind"
        );

        assert!(key_service.clear().is_ok());
    }
}
