use crate::{ErrorKind, Result, Storage};

/// `Storage` which returns `PermissionDenied` error for each function call.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnauthorizedStorage;

impl Storage for UnauthorizedStorage {
    fn clear<S: AsRef<[u8]>>(&self, _keyspace: S) -> Result<()> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn get<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        _keyspace: S,
        _key: K,
    ) -> Result<Option<Vec<u8>>> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn set<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        _keyspace: S,
        _key: K,
        _value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn delete<S: AsRef<[u8]>, K: AsRef<[u8]>>(
        &self,
        _keyspace: S,
        _key: K,
    ) -> Result<Option<Vec<u8>>> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn fetch_and_update<S, K, F>(&self, _: S, _: K, _: F) -> Result<Option<Vec<u8>>>
    where
        S: AsRef<[u8]>,
        K: AsRef<[u8]>,
        F: Fn(Option<&[u8]>) -> Result<Option<Vec<u8>>>,
    {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn keys<S: AsRef<[u8]>>(&self, _keyspace: S) -> Result<Vec<Vec<u8>>> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn contains_key<S: AsRef<[u8]>, K: AsRef<[u8]>>(&self, _keyspace: S, _key: K) -> Result<bool> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn keyspaces(&self) -> Result<Vec<Vec<u8>>> {
        Err(ErrorKind::PermissionDenied.into())
    }
}
