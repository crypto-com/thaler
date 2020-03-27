#![cfg(feature = "sled")]
use std::path::Path;
use std::sync::Arc;

use sled::{Config, Db};

use crate::storage::Storage;
use crate::{ErrorKind, Result, ResultExt};

/// Storage backed by Sled
#[derive(Clone)]
pub struct SledStorage(Arc<Db>);

impl SledStorage {
    /// Creates a new instance with specified path for data storage
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        if cfg!(test) {
            Ok(Self(Arc::new(
                Config::default()
                    .path(&path)
                    .temporary(true)
                    .open()
                    .chain(|| {
                        (
                            ErrorKind::InitializationError,
                            format!(
                                "Unable to initialize sled storage at path: {}",
                                path.as_ref().display()
                            ),
                        )
                    })?,
            )))
        } else {
            Ok(Self(Arc::new(sled::open(&path).chain(|| {
                (
                    ErrorKind::InitializationError,
                    format!(
                        "Unable to initialize sled storage at path: {}",
                        path.as_ref().display()
                    ),
                )
            })?)))
        }
    }
}

impl Storage for SledStorage {
    fn clear<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<()> {
        let tree = self.0.open_tree(keyspace.as_ref().to_vec()).chain(|| {
            (
                ErrorKind::StorageError,
                format!(
                    "Unable to open sled storage tree for keyspace: {}",
                    String::from_utf8_lossy(keyspace.as_ref())
                ),
            )
        })?;

        tree.clear().chain(|| {
            (
                ErrorKind::StorageError,
                format!(
                    "Unable to clear keyspace: {}",
                    String::from_utf8_lossy(keyspace.as_ref())
                ),
            )
        })?;
        Ok(())
    }

    fn get<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, keyspace: S, key: K) -> Result<Option<Vec<u8>>> {
        let tree = self.0.open_tree(keyspace.as_ref().to_vec()).chain(|| {
            (
                ErrorKind::StorageError,
                format!(
                    "Unable to open sled storage tree for keyspace: {}",
                    String::from_utf8_lossy(keyspace.as_ref())
                ),
            )
        })?;

        let value = tree.get(&key).chain(|| {
            (
                ErrorKind::StorageError,
                format!(
                    "Unable to find value for {} in keyspace: {}",
                    String::from_utf8_lossy(key.as_ref()),
                    String::from_utf8_lossy(keyspace.as_ref())
                ),
            )
        })?;
        let value = value.map(|inner| inner.to_vec());

        Ok(value)
    }

    fn set<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        let tree = self.0.open_tree(keyspace.as_ref().to_vec()).chain(|| {
            (
                ErrorKind::StorageError,
                format!(
                    "Unable to open sled storage tree for keyspace: {}",
                    String::from_utf8_lossy(keyspace.as_ref())
                ),
            )
        })?;

        let value = tree.insert(&key, value).chain(|| {
            (
                ErrorKind::StorageError,
                format!(
                    "Unable to insert value for {} in keyspace: {}",
                    String::from_utf8_lossy(key.as_ref()),
                    String::from_utf8_lossy(keyspace.as_ref())
                ),
            )
        })?;
        let value = value.map(|inner| inner.to_vec());

        Ok(value)
    }

    fn delete<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        keyspace: S,
        key: K,
    ) -> Result<Option<Vec<u8>>> {
        let tree = self.0.open_tree(keyspace.as_ref().to_vec()).chain(|| {
            (
                ErrorKind::StorageError,
                format!(
                    "Unable to open sled storage tree for keyspace: {}",
                    String::from_utf8_lossy(keyspace.as_ref())
                ),
            )
        })?;

        tree.remove(&key)
            .chain(|| {
                (
                    ErrorKind::StorageError,
                    format!(
                        "Unable to delete {} in keyspace: {}",
                        String::from_utf8_lossy(key.as_ref()),
                        String::from_utf8_lossy(keyspace.as_ref())
                    ),
                )
            })
            .map(|optional_value| optional_value.map(|value| value.to_vec()))
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
            let tree = self.0.open_tree(keyspace.as_ref().to_vec()).chain(|| {
                (
                    ErrorKind::StorageError,
                    format!(
                        "Unable to open sled storage tree for keyspace: {}",
                        String::from_utf8_lossy(keyspace.as_ref())
                    ),
                )
            })?;

            match tree.compare_and_swap(&key, tmp, next).chain(|| {
                (
                    ErrorKind::StorageError,
                    format!(
                        "Unable to compare-and-swap value for {} in keyspace: {}",
                        String::from_utf8_lossy(key.as_ref()),
                        String::from_utf8_lossy(keyspace.as_ref())
                    ),
                )
            })? {
                Ok(()) => return Ok(current),
                Err(new_current) => current = new_current.current.map(|inner| inner.to_vec()),
            }
        }
    }

    fn keys<S: AsRef<[u8]>>(&self, keyspace: S) -> Result<Vec<Vec<u8>>> {
        let tree = self.0.open_tree(keyspace.as_ref().to_vec()).chain(|| {
            (
                ErrorKind::StorageError,
                format!(
                    "Unable to open sled storage tree for keyspace: {}",
                    String::from_utf8_lossy(keyspace.as_ref())
                ),
            )
        })?;

        tree.iter()
            .keys()
            .map(|key| {
                let key = key.chain(|| {
                    (
                        ErrorKind::StorageError,
                        format!(
                            "Unable to retrieve keys for keyspace: {}",
                            String::from_utf8_lossy(keyspace.as_ref())
                        ),
                    )
                })?;
                Ok(key.as_ref().to_vec())
            })
            .collect()
    }

    fn contains_key<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, keyspace: S, key: K) -> Result<bool> {
        let tree = self.0.open_tree(keyspace.as_ref().to_vec()).chain(|| {
            (
                ErrorKind::StorageError,
                format!(
                    "Unable to open sled storage tree for keyspace: {}",
                    String::from_utf8_lossy(keyspace.as_ref())
                ),
            )
        })?;

        Ok(tree.contains_key(&key).chain(|| {
            (
                ErrorKind::StorageError,
                format!(
                    "Unable to check if {} exists in keyspace: {}",
                    String::from_utf8_lossy(key.as_ref()),
                    String::from_utf8_lossy(keyspace.as_ref())
                ),
            )
        })?)
    }

    fn keyspaces(&self) -> Result<Vec<Vec<u8>>> {
        let mut result = Vec::with_capacity(self.0.tree_names().len());
        for name in self.0.tree_names().iter() {
            let v: Vec<u8> = name.iter().copied().collect();
            result.push(v);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::SledStorage;
    use crate::Storage;

    use blake2::Blake2s;
    use chain_core::common::hash256;
    use tempfile::tempdir;

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

    #[test]
    fn check_sledstorage_ordering() {
        let dir = tempdir().expect("get tempdir in check_sledstorage_ordering");
        let dir_path = dir
            .path()
            .to_str()
            .expect("get folder path in check_sledstorage_ordering");
        let storage =
            SledStorage::new(dir_path).expect("get sled storage in check_sledstorage_ordering");
        let space = "default".as_bytes();
        let count = 512;
        let mut keylist: Vec<Vec<u8>> = vec![];
        let mut valuelist: Vec<Vec<u8>> = vec![];
        for i in 0..count {
            let data = format!("data {}", i);
            let hash = hash256::<Blake2s>(&data.as_bytes());
            assert!(32 == hash.len());
            let key_hex = hex::encode(&u64::to_be_bytes(i as u64));
            keylist.push(key_hex.as_bytes().to_vec());
            valuelist.push(hash.to_vec());
            storage
                .set(&space, key_hex.as_bytes(), hash.to_vec())
                .expect("set data");
        }
        assert!(keylist.len() == count);
        assert!(keylist.len() == valuelist.len());
        let keys = storage.keys(&space).expect("get keys");
        assert!(keylist.len() == keys.len());
        for i in 0..count {
            let key = keys[i].clone();
            let value = storage
                .get(&space, &key)
                .expect("get value")
                .expect("get value from option");
            assert!(keylist[i] == key);
            assert!(valuelist[i] == value);
        }
    }
}
