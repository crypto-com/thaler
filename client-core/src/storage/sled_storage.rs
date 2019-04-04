#![cfg(feature = "sled")]
use std::path::Path;

use failure::ResultExt;
use sled::{ConfigBuilder, Db};

use crate::storage::Storage;
use crate::{ErrorKind, Result};

/// Storage backed by Sled
#[derive(Clone)]
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
    /// data storage. Only for use in tests.
    #[cfg(test)]
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self(
            Db::start(ConfigBuilder::new().path(path).temporary(true).build())
                .context(ErrorKind::StorageInitializationError)?,
        ))
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

        let value = tree.set(key, value).context(ErrorKind::StorageError)?;
        let value = value.map(|inner| inner.to_vec());

        Ok(value)
    }

    fn keys<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<Vec<Vec<u8>>> {
        let tree = self
            .0
            .open_tree(keyspace.as_ref().to_vec())
            .context(ErrorKind::StorageError)?;

        tree.iter()
            .keys()
            .map(|key| Ok(key.context(ErrorKind::StorageError)?))
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
