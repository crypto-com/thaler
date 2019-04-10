#![cfg(test)]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use client_common::{Error, ErrorKind, Result, Storage};

/// Storage backed by `HashMap`
#[derive(Default)]
pub struct MemoryStorage(Arc<RwLock<HashMap<Vec<u8>, HashMap<Vec<u8>, Vec<u8>>>>>);

impl Storage for MemoryStorage {
    fn clear<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<()> {
        let mut memory = self
            .0
            .write()
            .map_err(|_| Error::from(ErrorKind::StorageError))?;
        let space = memory.get_mut(keyspace.as_ref());

        match space {
            None => Ok(()),
            Some(space) => {
                space.drain();
                Ok(())
            }
        }
    }

    fn get<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, keyspace: S, key: K) -> Result<Option<Vec<u8>>> {
        let memory = self
            .0
            .read()
            .map_err(|_| Error::from(ErrorKind::StorageError))?;
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
        let mut memory = self
            .0
            .write()
            .map_err(|_| Error::from(ErrorKind::StorageError))?;

        if !memory.contains_key(keyspace.as_ref()) {
            memory.insert(keyspace.as_ref().to_vec(), Default::default());
        }

        let space = memory.get_mut(keyspace.as_ref()).unwrap();

        Ok(space.insert(key.as_ref().to_vec(), value))
    }

    fn keys<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<Vec<Vec<u8>>> {
        let memory = self
            .0
            .read()
            .map_err(|_| Error::from(ErrorKind::StorageError))?;

        let space = memory.get(keyspace.as_ref());

        match space {
            None => Ok(Default::default()),
            Some(space) => Ok(space.keys().map(Clone::clone).collect::<Vec<Vec<u8>>>()),
        }
    }

    fn contains_key<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, keyspace: S, key: K) -> Result<bool> {
        let memory = self
            .0
            .read()
            .map_err(|_| Error::from(ErrorKind::StorageError))?;

        if memory.contains_key(keyspace.as_ref()) {
            let space = memory.get(keyspace.as_ref()).unwrap();

            Ok(space.contains_key(key.as_ref()))
        } else {
            Ok(false)
        }
    }

    fn keyspaces(&self) -> Result<Vec<Vec<u8>>> {
        let memory = self
            .0
            .read()
            .map_err(|_| Error::from(ErrorKind::StorageError))?;

        let keyspaces = memory.keys().map(Clone::clone).collect::<Vec<Vec<u8>>>();

        Ok(keyspaces)
    }
}
