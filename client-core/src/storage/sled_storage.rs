#![cfg(feature = "sled")]
use std::path::Path;

use failure::ResultExt;
use sled::{ConfigBuilder, Db};

use crate::storage::Storage;
use crate::{ErrorKind, Result};

/// Storage backed by Sled
pub struct SledStorage(Db);

impl SledStorage {
    /// Creates a new instance with specified path for data storage
    #[cfg(not(test))]
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self(
            Db::start(ConfigBuilder::new().path(path).build())
                .context(ErrorKind::StorageInitializationError)?,
        ))
    }

    /// Creates a new temporary instance (data will be deleted after the instance is dropped) with specified path for
    /// data storage
    #[cfg(test)]
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self(
            Db::start(ConfigBuilder::new().path(path).temporary(true).build())
                .context(ErrorKind::StorageInitializationError)?,
        ))
    }
}

impl Storage for SledStorage {
    fn clear(&self) -> Result<()> {
        self.0.clear().context(ErrorKind::StorageError)?;
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let value = self.0.get(key).context(ErrorKind::StorageError)?;
        let value = value.map(|inner| inner.to_vec());

        Ok(value)
    }

    fn set(&self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let value = self.0.set(key, value).context(ErrorKind::StorageError)?;
        let value = value.map(|inner| inner.to_vec());

        Ok(value)
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>> {
        self.0
            .iter()
            .keys()
            .map(|key| Ok(key.context(ErrorKind::StorageError)?))
            .collect()
    }

    fn contains_key(&self, key: &[u8]) -> Result<bool> {
        Ok(self.0.contains_key(key).context(ErrorKind::StorageError)?)
    }
}

#[cfg(test)]
mod tests {
    use super::SledStorage;
    use crate::Storage;

    #[test]
    fn check_flow() {
        let storage = SledStorage::new("./storage-test").expect("Unable to start sled storage");

        assert!(
            !storage
                .contains_key("key".as_bytes())
                .expect("Unable to connect to database"),
            "Key already in storage"
        );

        assert_eq!(
            None,
            storage.get("key".as_bytes()).expect("Unable to get value"),
            "Invalid value in get"
        );

        assert_eq!(
            None,
            storage
                .set("key".as_bytes(), "value".as_bytes().to_vec())
                .expect("Unable to set value"),
            "Invalid value in set"
        );

        assert_eq!(
            1,
            storage.keys().expect("Unable to get keys").len(),
            "Invalid number of keys present"
        );

        let value = storage
            .get("key".as_bytes())
            .expect("Unable to get value")
            .expect("Value not found");

        let value = std::str::from_utf8(&value).expect("Unable to deserialize bytes");

        assert_eq!("value", value, "Incorrect value found");
    }
}
