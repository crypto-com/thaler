#![cfg(feature = "sled")]
use std::path::Path;
use std::sync::Arc;

use failure::ResultExt;
use sled::{ConfigBuilder, Db};

use crate::storage::Storage;
use crate::{ErrorKind, Result};

/// Storage backed by Sled
#[derive(Clone)]
pub struct SledStorage(Arc<Db>);

impl SledStorage {
    /// Creates a new instance with specified path for data storage
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        if cfg!(test) {
            Ok(Self(Arc::new(
                Db::start(ConfigBuilder::new().path(path).temporary(true).build())
                    .context(ErrorKind::StorageInitializationError)?,
            )))
        } else {
            Ok(Self(Arc::new(
                Db::start(ConfigBuilder::new().path(path).build())
                    .context(ErrorKind::StorageInitializationError)?,
            )))
        }
    }
}

impl Storage for SledStorage {
    fn clear<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<()> {
        let tree = self
            .0
            .open_tree(keyspace.as_ref().to_vec())
            .context(ErrorKind::StorageError)?;

        tree.clear().context(ErrorKind::StorageError)?;
        Ok(())
    }

    fn get<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, keyspace: S, key: K) -> Result<Option<Vec<u8>>> {
        let tree = self
            .0
            .open_tree(keyspace.as_ref().to_vec())
            .context(ErrorKind::StorageError)?;

        let value = tree.get(key).context(ErrorKind::StorageError)?;
        let value = value.map(|inner| inner.to_vec());

        Ok(value)
    }

    fn set<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        let tree = self
            .0
            .open_tree(keyspace.as_ref().to_vec())
            .context(ErrorKind::StorageError)?;

        let value = tree.insert(key, value).context(ErrorKind::StorageError)?;
        let value = value.map(|inner| inner.to_vec());

        Ok(value)
    }

    fn fetch_and_update<S, K, F>(&self, keyspace: S, key: K, f: F) -> Result<Option<Vec<u8>>>
    where
        S: AsRef<[u8]>,
        K: AsRef<[u8]>,
        F: Fn(Option<&[u8]>) -> Result<Option<Vec<u8>>>,
    {
        let mut current = self.get(&keyspace, &key)?;

        loop {
            let tmp = current.as_ref().map(AsRef::as_ref);
            let next = f(tmp)?;
            let tree = self
                .0
                .open_tree(keyspace.as_ref().to_vec())
                .context(ErrorKind::StorageError)?;

            match tree.cas(&key, tmp, next).context(ErrorKind::StorageError)? {
                Ok(()) => return Ok(current),
                Err(new_current) => current = new_current.map(|inner| inner.to_vec()),
            }
        }
    }

    fn keys<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<Vec<Vec<u8>>> {
        let tree = self
            .0
            .open_tree(keyspace.as_ref().to_vec())
            .context(ErrorKind::StorageError)?;

        tree.iter()
            .keys()
            .map(|key| {
                let key = key.context(ErrorKind::StorageError)?;
                Ok(key.as_ref().to_vec())
            })
            .collect()
    }

    fn contains_key<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, keyspace: S, key: K) -> Result<bool> {
        let tree = self
            .0
            .open_tree(keyspace.as_ref().to_vec())
            .context(ErrorKind::StorageError)?;

        Ok(tree.contains_key(key).context(ErrorKind::StorageError)?)
    }

    fn keyspaces(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.0.tree_names())
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
                .contains_key("keyspace", "key")
                .expect("Unable to connect to database"),
            "Key already in storage"
        );

        assert_eq!(
            None,
            storage.get("keyspace", "key").expect("Unable to get value"),
            "Invalid value in get"
        );

        assert_eq!(
            None,
            storage
                .set("keyspace", "key", "value1".as_bytes().to_vec())
                .expect("Unable to set value"),
            "Invalid value in set"
        );

        assert_eq!(
            "value1",
            std::str::from_utf8(
                &storage
                    .fetch_and_update("keyspace", "key", |_| Ok(Some("value".as_bytes().to_vec())))
                    .unwrap()
                    .unwrap()
            )
            .expect("Unable to deserialize bytes")
        );

        assert_eq!(
            1,
            storage.keys("keyspace").expect("Unable to get keys").len(),
            "Invalid number of keys present"
        );

        let value = storage
            .get("keyspace", "key")
            .expect("Unable to get value")
            .expect("Value not found");

        let value = std::str::from_utf8(&value).expect("Unable to deserialize bytes");

        assert_eq!("value", value, "Incorrect value found");

        storage.clear("keyspace").expect("Unable to clean database");

        assert_eq!(
            0,
            storage.keys("keyspace").expect("Unable to get keys").len(),
            "Keys present even after clearing"
        );

        assert_eq!(
            2,
            storage.keyspaces().expect("Unable to get keyspaces").len(),
            "More than two keyspaces present"
        );
    }
}
