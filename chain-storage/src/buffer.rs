use std::collections::{hash_map::RandomState, HashMap};
use std::hash::{BuildHasher, Hash};

use kvdb::KeyValueDB;
use starling::traits::Exception;

use chain_core::state::account::{to_stake_key, StakedState, StakedStateAddress};

use super::account::{AccountStorage as StakingStorage, AccountWrapper, StarlingFixedKey};

pub trait Get {
    type Key;
    type Value;
    fn get(&self, key: &Self::Key) -> Option<Self::Value>;
}
pub trait Store: Get {
    fn set(&mut self, key: Self::Key, value: Self::Value);
}

/// Specialized to staking
pub trait GetStaking: Get<Key = StakedStateAddress, Value = StakedState> {
    fn get_or_default(&self, addr: &Self::Key) -> Self::Value {
        self.get(addr)
            .unwrap_or_else(|| Self::Value::default(*addr))
    }
}
impl<S> GetStaking for S where S: Get<Key = StakedStateAddress, Value = StakedState> {}

/// Specialized to staking
pub trait StoreStaking: Store<Key = StakedStateAddress, Value = StakedState> {
    fn set_staking(&mut self, staking: StakedState) {
        self.set(staking.address, staking)
    }
}
impl<S> StoreStaking for S where S: Store<Key = StakedStateAddress, Value = StakedState> {}
impl<S: KeyValueDB> Get for S {
    type Key = (u32, Vec<u8>);
    type Value = Vec<u8>;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        let (col, key) = key;
        self.get(*col, &key).unwrap()
    }
}
pub struct StakingGetter<'a> {
    storage: &'a StakingStorage,
    root: Option<StarlingFixedKey>,
}
impl<'a> StakingGetter<'a> {
    pub fn new(storage: &'a StakingStorage, root: Option<StarlingFixedKey>) -> Self {
        Self { storage, root }
    }
}
impl<'a> Get for StakingGetter<'a> {
    type Key = StakedStateAddress;
    type Value = StakedState;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        self.root.as_ref().and_then(|root| {
            self.storage
                .get_one(root, &to_stake_key(key))
                .unwrap()
                .map(|AccountWrapper(o)| o)
        })
    }
}

pub struct BufferStore<'a, S: Get, H: BuildHasher = RandomState> {
    storage: S,
    buffer: &'a mut HashMap<S::Key, S::Value, H>,
}

impl<'a, S: Get, H: BuildHasher> BufferStore<'a, S, H> {
    pub fn new(storage: S, buffer: &'a mut HashMap<S::Key, S::Value, H>) -> Self {
        Self { storage, buffer }
    }
}

impl<'a, S> Get for BufferStore<'a, S>
where
    S: Get,
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

impl<'a, S> Store for BufferStore<'a, S>
where
    S: Get,
    S::Key: Hash + Eq,
    S::Value: Clone,
{
    fn set(&mut self, key: Self::Key, value: Self::Value) {
        self.buffer.insert(key, value);
    }
}

pub struct BufferGetter<'a, S: Get, H: BuildHasher = RandomState> {
    storage: S,
    buffer: &'a HashMap<S::Key, S::Value, H>,
}

impl<'a, S: Get, H: BuildHasher> BufferGetter<'a, S, H> {
    pub fn new(storage: S, buffer: &'a HashMap<S::Key, S::Value, H>) -> Self {
        Self { storage, buffer }
    }
}

impl<'a, S> Get for BufferGetter<'a, S>
where
    S: Get,
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

pub type StakingBufferStore<'a, H = RandomState> = BufferStore<'a, StakingGetter<'a>, H>;
pub type StakingBufferGetter<'a, H = RandomState> = BufferGetter<'a, StakingGetter<'a>, H>;

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
impl<K, V> Store for MemStore<K, V>
where
    K: Hash + Eq,
    V: Clone,
{
    fn set(&mut self, key: Self::Key, value: Self::Value) {
        self.0.insert(key, value);
    }
}

/// Write buffered updates and update root key, should be called in abci commit event
pub fn flush_staking_storage<H: BuildHasher>(
    storage: &mut StakingStorage,
    root: Option<StarlingFixedKey>,
    buffer: HashMap<StakedStateAddress, StakedState, H>,
) -> Result<Option<StarlingFixedKey>, Exception> {
    let (mut keys, values): (Vec<_>, Vec<_>) = buffer
        .into_iter()
        .map(|(addr, v)| (to_stake_key(&addr), AccountWrapper(v)))
        .unzip();
    if keys.is_empty() {
        return Ok(root);
    }
    Ok(Some(storage.insert(root.as_ref(), &mut keys, &values)?))
}

pub fn flush_kvdb<S: KeyValueDB, H: BuildHasher>(
    storage: &mut S,
    buffer: HashMap<(u32, Vec<u8>), Vec<u8>, H>,
) -> std::io::Result<()> {
    let mut tx = storage.transaction();
    for ((col, key), value) in buffer.into_iter() {
        tx.put(col, &key, &value);
    }
    storage.write(tx)
}

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
mod tests {}
