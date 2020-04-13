//! # Buffered Storage
//!
//! > Kindly refer unit tests for usage tutorial.
//!
//! The basic idea is combining a read only storage and in memory HashMap, you get a buffered storage with read/write operations.
//!
//! - When read, it check the buffer first, if not exists then load from underlying storage.
//! - When write, it only write to the buffer.
//!
//! At commit time, grab a mutable access to the underlying storage and flush the content of buffer to it.
//!
//! Or simply drop the in-memory buffer if you don't want to commit it.
//!
//! It's useful to implement the separation of state between mempool and consensus connections.
//!
//! There are two kinds of storage type at play in chain-abci logic, staking merkle trie and
//! key-value database. The former only support get/set, the latter also support delete.
//!
//! We have three traits to capture the different cases:
//! - `Get`
//!   Read only(`get`) access to storages, can cover both merkle trie and kv db.
//! - `SimpleStore: Get`
//!   Simple read/write(`get`/`set`) access to storage, can cover both merkle trie and kv db.
//! - `Store: SimpleStore`
//!   Support `delete` on top of `SimpleStore`, only cover kv db.
//!
//! > _**NOTE:**_ `KeyValueDB` has an column type parameter, we combine it with key into a tuple:
//! `(u32, Vec<u8>)`, to keep the interface consistent with merkle trie.
//!
//! In the case of merkle trie, for convinence, we further specialize the `Get`/`SimpleStore` for staking to
//! `GetStaking`/`StoreStaking`.
//!
//! In the case of key-value database, the storage operation are further encapulated in
//! `chain-storage` crate, the other code rarely use low level operations directly.
//!
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};

use kvdb::KeyValueDB;

use chain_core::state::account::{StakedState, StakedStateAddress};

use crate::Storage;

pub trait Get {
    type Key;
    type Value;
    fn get(&self, key: &Self::Key) -> Option<Self::Value>;
}
pub trait SimpleStore: Get {
    fn set(&mut self, key: Self::Key, value: Self::Value);
}
pub trait Store: SimpleStore {
    fn delete(&mut self, key: Self::Key);
}

/// Specialized for kv db
pub trait StoreKV: Store<Key = (u32, Vec<u8>), Value = Vec<u8>> {}
impl<S> StoreKV for S where S: Store<Key = (u32, Vec<u8>), Value = Vec<u8>> {}
pub trait GetKV: Get<Key = (u32, Vec<u8>), Value = Vec<u8>> {}
impl<S> GetKV for S where S: Get<Key = (u32, Vec<u8>), Value = Vec<u8>> {}

impl<S: KeyValueDB> Get for S {
    type Key = (u32, Vec<u8>);
    type Value = Vec<u8>;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        let (col, key) = key;
        self.get(*col, &key).unwrap()
    }
}

/// Specialized for staking
pub trait GetStaking: Get<Key = StakedStateAddress, Value = StakedState> {
    fn get_or_default(&self, addr: &Self::Key) -> Self::Value {
        self.get(addr)
            .unwrap_or_else(|| Self::Value::default(*addr))
    }
}
impl<S> GetStaking for S where S: Get<Key = StakedStateAddress, Value = StakedState> {}

/// Specialized for staking
pub trait StoreStaking: SimpleStore<Key = StakedStateAddress, Value = StakedState> {
    fn set_staking(&mut self, staking: StakedState) {
        self.set(staking.address, staking)
    }
}
impl<S> StoreStaking for S where S: SimpleStore<Key = StakedStateAddress, Value = StakedState> {}

/// Generic readonly buffered storage implementation
pub struct BufferGetter<'a, S: Get, H> {
    storage: S,
    buffer: &'a HashMap<S::Key, S::Value, H>,
}

impl<'a, S: Get, H: BuildHasher> BufferGetter<'a, S, H> {
    pub fn new(storage: S, buffer: &'a HashMap<S::Key, S::Value, H>) -> Self {
        Self { storage, buffer }
    }
}

impl<'a, S, H> Get for BufferGetter<'a, S, H>
where
    S: Get,
    H: BuildHasher,
    S::Key: Hash + Eq,
    S::Value: Clone,
{
    type Key = S::Key;
    type Value = S::Value;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        self.buffer
            .get(key)
            .cloned()
            .or_else(|| self.storage.get(key))
    }
}

/// Generic buffered simple storage implementation
pub struct BufferSimpleStore<'a, S: Get, H> {
    storage: S,
    buffer: &'a mut HashMap<S::Key, S::Value, H>,
}

impl<'a, S: Get, H: BuildHasher> BufferSimpleStore<'a, S, H> {
    pub fn new(storage: S, buffer: &'a mut HashMap<S::Key, S::Value, H>) -> Self {
        Self { storage, buffer }
    }
}

impl<'a, S, H> Get for BufferSimpleStore<'a, S, H>
where
    S: Get,
    H: BuildHasher,
    S::Key: Hash + Eq,
    S::Value: Clone,
{
    type Key = S::Key;
    type Value = S::Value;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        self.buffer
            .get(key)
            .cloned()
            .or_else(|| self.storage.get(key))
    }
}

impl<'a, S, H> SimpleStore for BufferSimpleStore<'a, S, H>
where
    S: Get,
    H: BuildHasher,
    S::Key: Hash + Eq,
    S::Value: Clone,
{
    fn set(&mut self, key: Self::Key, value: Self::Value) {
        self.buffer.insert(key, value);
    }
}

/// Generic buffered storage implementation
pub struct BufferStore<'a, S: Get, H> {
    storage: &'a S,
    // None means deletion, Some means set.
    buffer: &'a mut HashMap<S::Key, Option<S::Value>, H>,
}

impl<'a, S: Get, H: BuildHasher> BufferStore<'a, S, H> {
    pub fn new(storage: &'a S, buffer: &'a mut HashMap<S::Key, Option<S::Value>, H>) -> Self {
        Self { storage, buffer }
    }
}

impl<'a, S, H> Get for BufferStore<'a, S, H>
where
    S: Get,
    H: BuildHasher,
    S::Key: Hash + Eq,
    S::Value: Clone,
{
    type Key = S::Key;
    type Value = S::Value;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        self.buffer
            .get(key)
            .cloned()
            .unwrap_or_else(|| self.storage.get(key))
    }
}

impl<'a, S, H> SimpleStore for BufferStore<'a, S, H>
where
    S: Get,
    H: BuildHasher,
    S::Key: Hash + Eq,
    S::Value: Clone,
{
    fn set(&mut self, key: Self::Key, value: Self::Value) {
        self.buffer.insert(key, Some(value));
    }
}

impl<'a, S, H> Store for BufferStore<'a, S, H>
where
    S: Get,
    H: BuildHasher,
    S::Key: Hash + Eq,
    S::Value: Clone,
{
    fn delete(&mut self, key: Self::Key) {
        self.buffer.insert(key, None);
    }
}

/// Dummy storage implemented with a HashMap in memory.
#[derive(Debug, Clone)]
pub struct MemStore<K: Hash + Eq, V>(HashMap<K, V>);

impl<K: Hash + Eq, V> MemStore<K, V> {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
}

impl<K: Hash + Eq, V> Default for MemStore<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> Get for MemStore<K, V>
where
    K: Hash + Eq,
    V: Clone,
{
    type Key = K;
    type Value = V;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        self.0.get(key).cloned()
    }
}
impl<K, V> SimpleStore for MemStore<K, V>
where
    K: Hash + Eq,
    V: Clone,
{
    fn set(&mut self, key: Self::Key, value: Self::Value) {
        self.0.insert(key, value);
    }
}

impl<K, V> Store for MemStore<K, V>
where
    K: Hash + Eq,
    V: Clone,
{
    fn delete(&mut self, key: Self::Key) {
        self.0.remove(&key);
    }
}

/// Buffer used for staking storage
pub type StakingBuffer = HashMap<StakedStateAddress, StakedState>;

/// Buffer used for key-value storage
pub type KVBuffer = HashMap<(u32, Vec<u8>), Option<Vec<u8>>>;

/// Flush buffer to kv db
pub fn flush_kvdb<S: KeyValueDB + ?Sized>(storage: &S, buffer: KVBuffer) -> std::io::Result<()> {
    let mut tx = storage.transaction();
    for ((col, key), value) in buffer.into_iter() {
        if let Some(val) = &value {
            tx.put(col, &key, val);
        } else {
            tx.delete(col, &key);
        }
    }
    storage.write(tx)
}

/// Flush buffer to storage
pub fn flush_storage(storage: &mut Storage, buffer: KVBuffer) -> std::io::Result<()> {
    let tx = storage.get_or_create_tx();
    for ((col, key), value) in buffer.into_iter() {
        if let Some(val) = &value {
            tx.put(col, &key, val);
        } else {
            tx.delete(col, &key);
        }
    }
    storage.persist_write()
}

/// Flush buffer to memstore
pub fn flush_memstore<K, V, H: BuildHasher>(storage: &mut MemStore<K, V>, buffer: HashMap<K, V, H>)
where
    K: Hash + Eq,
    V: Clone,
{
    for (k, v) in buffer.into_iter() {
        storage.set(k, v);
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    use kvdb::KeyValueDB;
    use kvdb_memorydb::{create as create_memorydb, InMemory};

    use super::*;

    // demonstrate how to use buffered store in the chain abci app.
    struct App<D: KeyValueDB> {
        kvdb: D,
        tmp_kv_buffer: KVBuffer,
        kv_buffer: KVBuffer,
    }

    impl<D: KeyValueDB> App<D> {
        fn new(kvdb: D) -> Self {
            Self {
                kvdb,
                tmp_kv_buffer: HashMap::new(),
                kv_buffer: HashMap::new(),
            }
        }

        fn commit(&mut self) {
            flush_kvdb(&self.kvdb, mem::take(&mut self.kv_buffer)).unwrap();
            self.tmp_kv_buffer.clear();
        }

        fn kv_store(&mut self) -> impl StoreKV + '_ {
            BufferStore::new(&self.kvdb, &mut self.kv_buffer)
        }

        fn tmp_kv_store(&mut self) -> impl StoreKV + '_ {
            BufferStore::new(&self.kvdb, &mut self.tmp_kv_buffer)
        }
    }

    impl App<InMemory> {
        fn new_memory() -> Self {
            Self::new(create_memorydb(1))
        }
    }

    #[test]
    fn check_kvdb() {
        let mut app = App::new_memory();
        let col0 = 0;
        // let col1 = 1;
        let key1 = (col0, "key1".as_bytes().to_owned());
        let value1 = "value1".as_bytes().to_owned();
        let key2 = (col0, "key2".as_bytes().to_owned());
        let value2 = "value2".as_bytes().to_owned();

        // kv store can set and get key1
        app.kv_store().set(key1.clone(), value1.clone());
        assert_eq!(&app.kv_store().get(&key1).unwrap(), &value1);

        // key1 not in tmp kv store
        assert_eq!(app.tmp_kv_store().get(&key1), None);

        // tmp kv store can set and get key2
        app.tmp_kv_store().set(key2.clone(), value2.clone());
        assert_eq!(&app.tmp_kv_store().get(&key2).unwrap(), &value2);

        // kv store don't have key2
        assert_eq!(app.kv_store().get(&key2), None);

        // kv store can delete key1
        app.kv_store().delete(key1.clone());
        assert_eq!(app.kv_store().get(&key1), None);

        // kv store set key1 back
        app.kv_store().set(key1.clone(), value1.clone());

        app.commit();

        // after commit, both store have key1, don't have key2
        assert_eq!(&app.kv_store().get(&key1).unwrap(), &value1);
        assert_eq!(app.kv_store().get(&key2), None);
        assert_eq!(&app.tmp_kv_store().get(&key1).unwrap(), &value1);
        assert_eq!(app.tmp_kv_store().get(&key2), None);
    }

    #[test]
    fn check_memstore() {
        let store: MemStore<String, String> = MemStore::new();
        let mut buffer = HashMap::new();
        let key1 = "key1".to_owned();
        let value1 = "value1".to_owned();
        {
            let mut bufstore = BufferStore::new(&store, &mut buffer);
            bufstore.set(key1.clone(), value1.clone());
            assert_eq!(&bufstore.get(&key1).unwrap(), &value1);
        }

        // key1 is written to buffer, rather than store.
        assert_eq!(store.get(&key1), None);
        assert_eq!(buffer.get(&key1).unwrap(), &Some(value1));

        {
            let mut bufstore = BufferStore::new(&store, &mut buffer);
            bufstore.delete(key1.clone());
        }

        // deletion also happens in buffer.
        assert!(buffer.get(&key1).unwrap().is_none());
    }
}
