use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::{Error, ErrorKind, Result, Storage};

/// Storage backed by `HashMap`
#[allow(clippy::type_complexity)]
#[derive(Debug, Default, Clone)]
pub struct MemoryStorage(Arc<RwLock<HashMap<Vec<u8>, HashMap<Vec<u8>, Vec<u8>>>>>);

impl Storage for MemoryStorage {
    fn flush(&self) -> Result<()> {
        Ok(())
    }
    fn clear<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<()> {
        let mut memory = self.0.write().map_err(|_| {
            Error::new(
                ErrorKind::StorageError,
                "Unable to acquire write lock on memory storage",
            )
        })?;

        if let Some(ref mut space) = memory.get_mut(keyspace.as_ref()) {
            space.drain();
        }

        Ok(())
    }

    fn get<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, keyspace: S, key: K) -> Result<Option<Vec<u8>>> {
        let memory = self.0.read().map_err(|_| {
            Error::new(
                ErrorKind::StorageError,
                "Unable to acquire read lock on memory storage",
            )
        })?;
        let value = memory
            .get(keyspace.as_ref())
            .and_then(|space| space.get(key.as_ref()))
            .map(Clone::clone);

        Ok(value)
    }

    fn set<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        let mut memory = self.0.write().map_err(|_| {
            Error::new(
                ErrorKind::StorageError,
                "Unable to acquire write lock on memory storage",
            )
        })?;

        if !memory.contains_key(keyspace.as_ref()) {
            memory.insert(keyspace.as_ref().to_vec(), Default::default());
        }

        let space = memory.get_mut(keyspace.as_ref()).unwrap();

        Ok(space.insert(key.as_ref().to_vec(), value))
    }

    fn delete<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
    ) -> Result<Option<Vec<u8>>> {
        let mut memory = self.0.write().map_err(|_| {
            Error::new(
                ErrorKind::StorageError,
                "Unable to acquire write lock on memory storage",
            )
        })?;

        Ok(memory
            .get_mut(keyspace.as_ref())
            .and_then(|keyspace| keyspace.remove(key.as_ref())))
    }

    fn fetch_and_update<S, K, F>(&self, keyspace: S, key: K, f: F) -> Result<Option<Vec<u8>>>
    where
        S: AsRef<[u8]>,
        K: AsRef<[u8]>,
        F: Fn(Option<&[u8]>) -> Result<Option<Vec<u8>>>,
    {
        let mut memory = self.0.write().map_err(|_| {
            Error::new(
                ErrorKind::StorageError,
                "Unable to acquire write lock on memory storage",
            )
        })?;

        if !memory.contains_key(keyspace.as_ref()) {
            memory.insert(keyspace.as_ref().to_vec(), Default::default());
        }

        let space = memory.get_mut(keyspace.as_ref()).unwrap();

        let current = space.get(key.as_ref()).map(AsRef::as_ref);

        let next = f(current)?;

        match next {
            None => Ok(space.remove(key.as_ref())),
            Some(next) => Ok(space.insert(key.as_ref().to_vec(), next)),
        }
    }

    fn keys<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<Vec<Vec<u8>>> {
        let memory = self.0.read().map_err(|_| {
            Error::new(
                ErrorKind::StorageError,
                "Unable to acquire read lock on memory storage",
            )
        })?;

        let keys = memory
            .get(keyspace.as_ref())
            .map(|space| space.keys().map(Clone::clone).collect::<Vec<Vec<u8>>>())
            .unwrap_or_default();

        Ok(keys)
    }

    fn contains_key<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, keyspace: S, key: K) -> Result<bool> {
        let memory = self.0.read().map_err(|_| {
            Error::new(
                ErrorKind::StorageError,
                "Unable to acquire read lock on memory storage",
            )
        })?;

        let contains_key = memory
            .get(keyspace.as_ref())
            .map_or(false, |space| space.contains_key(key.as_ref()));

        Ok(contains_key)
    }

    fn keyspaces(&self) -> Result<Vec<Vec<u8>>> {
        let memory = self.0.read().map_err(|_| {
            Error::new(
                ErrorKind::StorageError,
                "Unable to acquire read lock on memory storage",
            )
        })?;

        let keyspaces = memory.keys().map(Clone::clone).collect::<Vec<Vec<u8>>>();

        Ok(keyspaces)
    }
}
