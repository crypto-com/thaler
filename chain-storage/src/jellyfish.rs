use std::convert::TryInto;
use std::mem;

use anyhow::Result;
use jellyfish_merkle::{
    node_type::{LeafNode, Node, NodeKey},
    JellyfishMerkleTree, StaleNodeIndex, TreeReader,
};
use kvdb::KeyValueDB;
use libra_crypto::HashValue;
use parity_scale_codec::{Decode, Encode};

use chain_core::state::account::{to_stake_key, StakedState, StakedStateAddress};
use chain_core::state::tendermint::BlockHeight;

use super::{COL_TRIE_NODE, COL_TRIE_STALED};
use crate::buffer::{BufferGetter, BufferSimpleStore, Get, GetKV, StakingBuffer, StoreKV};

pub struct KVReader<'a, S: GetKV>(&'a S);
impl<'a, S: GetKV> KVReader<'a, S> {
    pub fn new(storage: &'a S) -> Self {
        Self(storage)
    }
}

impl<'a, S: GetKV> TreeReader for KVReader<'a, S> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        self.0
            .get(&(COL_TRIE_NODE, node_key.encode()?))
            .map(|bytes| Node::decode(&bytes))
            .transpose()
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        unimplemented!("this feature is only used in merkle tree restore which we don't need yet");
    }
}

pub struct StakingGetter<'a, S: GetKV> {
    storage: &'a S,
    block_height: BlockHeight,
}

impl<'a, S: GetKV> StakingGetter<'a, S> {
    pub fn new(storage: &'a S, block_height: BlockHeight) -> Self {
        Self {
            storage,
            block_height,
        }
    }
}

impl<'a, S: GetKV> Get for StakingGetter<'a, S> {
    type Key = StakedStateAddress;
    type Value = StakedState;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        JellyfishMerkleTree::new(&KVReader::new(self.storage))
            .get_with_proof(HashValue::new(to_stake_key(key)), self.block_height.into())
            .expect("merkle trie internal error")
            .0
            .map(|blob| {
                StakedState::decode(&mut blob.as_ref()).expect("merkle trie storage corrupted")
            })
    }
}

/// Specialized for staking
pub type StakingBufferStore<'a, S, H> = BufferSimpleStore<'a, StakingGetter<'a, S>, H>;
/// Specialized for staking
pub type StakingBufferGetter<'a, S, H> = BufferGetter<'a, StakingGetter<'a, S>, H>;

/// Flush buffer to merkle trie
pub fn flush_stakings<S: StoreKV>(
    storage: &mut S,
    block_height: BlockHeight,
    buffer: StakingBuffer,
) -> Result<HashValue> {
    let reader = KVReader::new(storage);
    let tree = JellyfishMerkleTree::new(&reader);
    let (root_hashes, batch) = tree.put_blob_sets(
        vec![buffer
            .values()
            .map(|staking| (HashValue::new(staking.key()), staking.encode().into()))
            .collect::<Vec<_>>()],
        block_height.into(),
    )?;
    assert_eq!(root_hashes.len(), 1);
    for (key, node) in batch.node_batch.iter() {
        storage.set((COL_TRIE_NODE, key.encode()?), node.encode()?);
    }
    for key in batch.stale_node_index_batch {
        storage.set((COL_TRIE_STALED, encode_stale_node_index(&key)?), vec![]);
    }
    Ok(root_hashes[0])
}

/// Collect staled nodes
pub fn collect_stale_node_indices<S: KeyValueDB>(
    storage: &S,
    stale_since: BlockHeight,
) -> Vec<StaleNodeIndex> {
    storage
        .iter_from_prefix(COL_TRIE_STALED, &stale_since.value().to_be_bytes())
        .map(|(key, _)| decode_stale_node_index(&key).expect("storage corrupted"))
        .collect::<Vec<_>>()
}

fn encode_stale_node_index(index: &StaleNodeIndex) -> Result<Vec<u8>> {
    let mut encoded = vec![];
    // Encoded as big endian to keep the numeric order
    encoded.extend_from_slice(&index.stale_since_version.to_be_bytes());
    encoded.extend(index.node_key.encode()?);

    Ok(encoded)
}

fn decode_stale_node_index(data: &[u8]) -> Result<StaleNodeIndex> {
    let version_size = mem::size_of::<u64>();

    let stale_since_version = u64::from_be_bytes(data[..version_size].try_into().unwrap());
    let node_key = NodeKey::decode(&data[version_size..])?;

    Ok(StaleNodeIndex {
        stale_since_version,
        node_key,
    })
}

#[cfg(test)]
mod tests {
    use kvdb_memorydb::{create as create_memorydb, InMemory};

    use super::*;
    use crate::buffer::{flush_kvdb, BufferStore, GetStaking, KVBuffer, StoreStaking};
    use crate::NUM_COLUMNS;

    struct App {
        storage: InMemory,
        kv_buffer: KVBuffer,
        staking_buffer: StakingBuffer,
        block_height: BlockHeight,
        root_hash: HashValue,
    }
    impl App {
        fn new() -> Self {
            Self {
                storage: create_memorydb(NUM_COLUMNS),
                kv_buffer: KVBuffer::new(),
                staking_buffer: StakingBuffer::new(),
                block_height: BlockHeight::genesis(),
                root_hash: HashValue::zero(),
            }
        }

        fn staking_getter(&self) -> impl GetStaking + '_ {
            StakingGetter::new(&self.storage, self.block_height.saturating_sub(1))
        }

        fn staking_store(&mut self) -> impl StoreStaking + '_ {
            StakingBufferStore::new(
                StakingGetter::new(&self.storage, self.block_height),
                &mut self.staking_buffer,
            )
        }

        fn commit(&mut self) {
            self.root_hash = self.flush_stakings().unwrap();
            self.flush_kvdb().unwrap();
            self.block_height = self.block_height.saturating_add(1);
        }

        fn flush_stakings(&mut self) -> Result<HashValue> {
            flush_stakings(
                &mut BufferStore::new(&self.storage, &mut self.kv_buffer),
                self.block_height,
                mem::take(&mut self.staking_buffer),
            )
        }

        fn flush_kvdb(&mut self) -> Result<()> {
            flush_kvdb(&self.storage, mem::take(&mut self.kv_buffer))?;
            Ok(())
        }
    }

    #[test]
    fn check_basic() {
        let mut app = App::new();
        let stakings = (0..10)
            .map(|i| StakedState::default(StakedStateAddress::BasicRedeem([0x01 + i; 20].into())))
            .collect::<Vec<_>>();
        let root_hashes = stakings
            .iter()
            .map(|staking| {
                app.staking_store().set_staking(staking.clone());
                assert_eq!(app.staking_buffer.len(), 1);
                app.commit();
                assert_eq!(app.staking_buffer.len(), 0);
                assert_eq!(app.kv_buffer.len(), 0);
                app.root_hash
            })
            .collect::<Vec<_>>();

        // get from current version
        for staking in stakings.iter() {
            assert_eq!(
                app.staking_getter().get(&staking.address).as_ref(),
                Some(staking)
            );
        }
        // get from history version
        for (i, staking) in stakings.iter().enumerate() {
            assert_eq!(
                StakingGetter::new(&app.storage, (i as u64).into())
                    .get(&staking.address)
                    .as_ref(),
                Some(staking)
            );
        }

        let mut staking0 = stakings[0].clone();
        staking0.nonce = 1;
        app.staking_store().set_staking(staking0.clone());
        app.commit();

        assert_eq!(
            app.staking_getter().get(&staking0.address).as_ref(),
            Some(&staking0)
        );

        check_proof(&mut app, &stakings, &root_hashes, &staking0);
    }

    fn check_proof(
        app: &mut App,
        stakings: &[StakedState],
        root_hashes: &[HashValue],
        staking0: &StakedState,
    ) {
        let reader = KVReader::new(&app.storage);
        let tree = JellyfishMerkleTree::new(&reader);

        // inclusion proof
        for (i, (staking, root_hash)) in stakings.iter().zip(root_hashes.iter()).enumerate() {
            let hash = HashValue::new(staking.key());
            let (mvalue, proof) = tree.get_with_proof(hash, i as u64).unwrap();
            assert_eq!(mvalue, Some(staking.encode().into()));
            proof.verify(*root_hash, hash, mvalue.as_ref()).unwrap();
        }
        {
            let hash = HashValue::new(staking0.key());
            let (mvalue, proof) = tree.get_with_proof(hash, stakings.len() as u64).unwrap();
            assert_eq!(mvalue, Some(staking0.encode().into()));
            proof.verify(app.root_hash, hash, mvalue.as_ref()).unwrap();
        }

        // exclusion proof
        {
            let hash = HashValue::new(stakings[1].key());
            let (mvalue, proof) = tree.get_with_proof(hash, 0).unwrap();
            assert_eq!(mvalue, None);
            proof.verify(root_hashes[0], hash, None).unwrap();
        }
    }
}
