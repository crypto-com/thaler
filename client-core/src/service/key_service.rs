use zeroize::Zeroize;

use client_common::Result;
use client_common::{PrivateKey, SecKey, SecureStorage, Storage};

const KEYSPACE: &str = "core_key";

/// Maintains mapping `wallet-name -> private-key`
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

    /// Adds a new wallet_name-private keypair to storage
    pub fn add_wallet_private_key(
        &self,
        wallet_name: &str,
        private_key: &PrivateKey,
        enckey: &SecKey,
    ) -> Result<()> {
        self.storage
            .set_secure(
                KEYSPACE,
                wallet_name.as_bytes(),
                private_key.serialize(),
                enckey,
            )
            .map(|_| ())
    }

    /// Retrieves private key corresponding to given wallet name
    pub fn wallet_private_key(
        &self,
        wallet_name: &str,
        enckey: &SecKey,
    ) -> Result<Option<PrivateKey>> {
        let private_key_bytes =
            self.storage
                .get_secure(KEYSPACE, wallet_name.as_bytes(), enckey)?;

        private_key_bytes
            .map(|mut private_key_bytes| {
                let private_key = PrivateKey::deserialize_from(&private_key_bytes)?;
                private_key_bytes.zeroize();
                Ok(private_key)
            })
            .transpose()
    }

    /// Delete private key
    pub fn delete_wallet_private_key(&self, wallet_name: &str, enckey: &SecKey) -> Result<()> {
        self.storage.delete(KEYSPACE, wallet_name.as_bytes())?;
        self.storage
            .get_secure(KEYSPACE, wallet_name.as_bytes(), enckey)?;
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
        let name = "Default";

        key_service
            .add_wallet_private_key(name, &private_key, &enckey)
            .expect("Unable to generate private key");

        let retrieved_private_key = key_service
            .wallet_private_key(name, &enckey)
            .unwrap()
            .unwrap();

        assert_eq!(private_key, retrieved_private_key);

        let error = key_service
            .wallet_private_key(name, &incorrect_enckey)
            .expect_err("Decryption worked with incorrect enckey");

        assert_eq!(
            error.kind(),
            ErrorKind::DecryptionError,
            "Invalid error kind"
        );

        assert!(key_service.clear().is_ok());
    }
}
