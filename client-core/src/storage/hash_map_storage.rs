#![cfg(any(test, feature = "hash-map"))]
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::{Error, ErrorKind, Result, Storage};

/// Storage backed by HashMap.
#[derive(Default)]
pub struct HashMapStorage(Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>);

impl Storage for HashMapStorage {
    fn clear(&self) -> Result<()> {
        let mut map = self
            .0
            .lock()
            .map_err(|_| Error::from(ErrorKind::LockError))?;
        map.clear();

        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let map = self
            .0
            .lock()
            .map_err(|_| Error::from(ErrorKind::LockError))?;

        let value = map.get(key).map(Clone::clone);

        Ok(value)
    }

    fn set(&self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let mut map = self
            .0
            .lock()
            .map_err(|_| Error::from(ErrorKind::LockError))?;

        let value = map.insert(key.to_vec(), value);

        Ok(value)
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>> {
        let map = self
            .0
            .lock()
            .map_err(|_| Error::from(ErrorKind::LockError))?;

        let keys = map.keys().map(|key| key.to_vec()).collect();

        Ok(keys)
    }

    fn contains_key(&self, key: &[u8]) -> Result<bool> {
        let map = self
            .0
            .lock()
            .map_err(|_| Error::from(ErrorKind::LockError))?;

        Ok(map.contains_key(key))
    }
}
