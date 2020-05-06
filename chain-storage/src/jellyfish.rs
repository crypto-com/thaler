use std::convert::TryInto;
use std::mem;
use std::sync::Arc;

use anyhow::{ensure, Result};
use jellyfish_merkle::iterator::JellyfishMerkleIterator;
use jellyfish_merkle::{
    node_type::{LeafNode, Node, NodeKey},
    HashValue, JellyfishMerkleTree, StaleNodeIndex, TreeReader,
};
use kvdb::KeyValueDB;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

use chain_core::common::{H256, HASH_SIZE_256};
use chain_core::init::coin::{sum_coins, Coin, CoinError};
use chain_core::state::account::{to_stake_key, StakedState, StakedStateAddress};
use chain_core::state::tendermint::BlockHeight;

use super::{COL_TRIE_NODE, COL_TRIE_STALED};
use crate::buffer::{
    BufferGetter, BufferSimpleStore, Get, GetKV, MemStore, StakingBuffer, StoreKV,
};

pub use jellyfish_merkle::Version;

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
    version: Version,
}

impl<'a, S: GetKV> StakingGetter<'a, S> {
    pub fn new(storage: &'a S, version: Version) -> Self {
        Self { storage, version }
    }
}

impl<'a, S: GetKV> Get for StakingGetter<'a, S> {
    type Key = StakedStateAddress;
    type Value = StakedState;
    fn get(&self, key: &Self::Key) -> Option<Self::Value> {
        // treat non exist version as empty set.
        self.storage.get(&(
            COL_TRIE_NODE,
            NodeKey::new_empty_path(self.version).encode().unwrap(),
        ))?;
        JellyfishMerkleTree::new(&KVReader::new(self.storage))
            .get_with_proof(HashValue::new(to_stake_key(key)), self.version)
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

/// Put stakings into the merkle tree backed by key-value storage.
pub fn put_stakings<'a, S: StoreKV>(
    storage: &mut S,
    version: Version,
    stakings: impl Iterator<Item = &'a StakedState>,
) -> Result<H256> {
    let reader = KVReader::new(storage);
    let tree = JellyfishMerkleTree::new(&reader);
    let stakings = stakings
        .map(|staking| (HashValue::new(staking.key()), staking.encode().into()))
        .collect::<Vec<_>>();
    ensure!(!stakings.is_empty(), "can't put empty stakings");
    let (root_hashes, batch) = tree.put_blob_sets(vec![stakings], version)?;
    assert_eq!(root_hashes.len(), 1);
    for (key, node) in batch.node_batch.iter() {
        storage.set((COL_TRIE_NODE, key.encode()?), node.encode()?);
    }
    for key in batch.stale_node_index_batch {
        storage.set((COL_TRIE_STALED, encode_stale_node_index(&key)?), vec![]);
    }
    Ok(*root_hashes[0].as_ref())
}

/// Flush buffer to merkle trie
pub fn flush_stakings<S: StoreKV>(
    storage: &mut S,
    version: Version,
    buffer: StakingBuffer,
) -> Result<H256> {
    put_stakings(storage, version, buffer.values())
}

/// Compute root hash of stakings in memory
pub fn compute_staking_root(stakings: &[StakedState]) -> H256 {
    let mut store = MemStore::new();
    put_stakings(&mut store, 0, stakings.iter()).expect("jellyfish error with in memory storage")
}

/// Wrap `SparseMerkleProof` to support SCALE encoding
#[derive(Debug, Clone)]
pub struct SparseMerkleProof(jellyfish_merkle::SparseMerkleProof);

impl Encode for SparseMerkleProof {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        // leaf
        match self.0.leaf() {
            None => dest.push_byte(0),
            Some((hash1, hash2)) => {
                dest.push_byte(1);
                dest.write(hash1.as_ref());
                dest.write(hash2.as_ref());
            }
        }

        // siblings
        let siblings = self
            .0
            .siblings()
            .iter()
            .map(HashValue::as_ref)
            .collect::<Vec<_>>();
        dest.push(&siblings);
    }

    fn size_hint(&self) -> usize {
        let len = self.0.siblings().len();
        HASH_SIZE_256 * 2 + 1 + mem::size_of::<u32>() + len * HASH_SIZE_256
    }
}

impl Decode for SparseMerkleProof {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let leaf = match input.read_byte()? {
            0 => None,
            1 => Some((
                HashValue::new(H256::decode(input)?),
                HashValue::new(H256::decode(input)?),
            )),
            _ => return Err("Invalid variant in Option<_> SparseMerkleProof::leaf".into()),
        };

        let siblings = <Vec<H256>>::decode(input)?
            .into_iter()
            .map(HashValue::new)
            .collect::<Vec<_>>();
        Ok(SparseMerkleProof(jellyfish_merkle::SparseMerkleProof::new(
            leaf, siblings,
        )))
    }
}

impl SparseMerkleProof {
    pub fn verify(
        &self,
        root_hash: H256,
        address: &StakedStateAddress,
        value: Option<&StakedState>,
    ) -> Result<()> {
        self.0.verify(
            HashValue::new(root_hash),
            HashValue::new(to_stake_key(address)),
            value.map(|staking| staking.encode().into()).as_ref(),
        )
    }
}

/// Get with proof from underlying storage.
pub fn get_with_proof<S: GetKV>(
    storage: &S,
    version: Version,
    key: &StakedStateAddress,
) -> (Option<StakedState>, SparseMerkleProof) {
    let (blob, proof) = JellyfishMerkleTree::new(&KVReader::new(storage))
        .get_with_proof(HashValue::new(to_stake_key(key)), version)
        .expect("merkle trie internal error");
    (
        blob.map(|blob| {
            StakedState::decode(&mut blob.as_ref()).expect("merkle trie storage corrupted")
        }),
        SparseMerkleProof(proof),
    )
}

/// Collect staled nodes
pub fn collect_stale_node_indices<S: KeyValueDB>(
    storage: &S,
    stale_since: BlockHeight,
) -> Vec<StaleNodeIndex> {
    storage
        .iter_with_prefix(COL_TRIE_STALED, &stale_since.value().to_be_bytes())
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

/// Iterate through all stakings
pub fn iter_stakings<S: GetKV>(
    storage: &S,
    version: Version,
) -> impl Iterator<Item = StakedState> + '_ {
    JellyfishMerkleIterator::new(
        Arc::new(KVReader::new(storage)),
        version,
        HashValue::new([0u8; 32]),
    )
    .expect("jellyfish storage internal error")
    .map(|mblob| {
        let (key, blob) = mblob.expect("jellyfish storage internal error");
        let staking = StakedState::decode(&mut blob.as_ref()).expect("jellyfish storage corrupted");
        assert_eq!(key, HashValue::new(staking.key()));
        staking
    })
}

/// Sum all `bonded + unbonded` of all stakings
pub fn sum_staking_coins<S: GetKV>(
    storage: &S,
    version: Version,
) -> std::result::Result<Coin, CoinError> {
    sum_coins(
        iter_stakings(storage, version)
            .flat_map(|staking| vec![staking.bonded, staking.unbonded].into_iter()),
    )
}

#[cfg(test)]
mod tests {
    use jellyfish_merkle::node_type::Node;
    use jellyfish_merkle::{AccountStateBlob, CryptoHash};
    use kvdb_memorydb::{create as create_memorydb, InMemory};

    use super::*;
    use crate::buffer::{flush_kvdb, BufferStore, GetStaking, KVBuffer, StoreStaking};
    use crate::NUM_COLUMNS;

    struct App {
        storage: InMemory,
        kv_buffer: KVBuffer,
        staking_buffer: StakingBuffer,
        version: Version,
        root_hash: H256,
    }
    impl App {
        fn new() -> Self {
            Self {
                storage: create_memorydb(NUM_COLUMNS),
                kv_buffer: KVBuffer::new(),
                staking_buffer: StakingBuffer::new(),
                version: 0,
                root_hash: [0; 32],
            }
        }

        fn staking_getter(&self) -> impl GetStaking + '_ {
            StakingGetter::new(&self.storage, self.version.saturating_sub(1))
        }

        fn staking_store(&mut self) -> impl StoreStaking + '_ {
            StakingBufferStore::new(
                StakingGetter::new(&self.storage, self.version),
                &mut self.staking_buffer,
            )
        }

        fn commit(&mut self) {
            self.root_hash = self.flush_stakings().unwrap();
            self.flush_kvdb().unwrap();
            self.version = self.version.saturating_add(1);
        }

        fn flush_stakings(&mut self) -> Result<H256> {
            flush_stakings(
                &mut BufferStore::new(&self.storage, &mut self.kv_buffer),
                self.version,
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
            .map(|i| StakedState {
                bonded: Coin::one(),
                unbonded: Coin::one(),
                ..StakedState::default(StakedStateAddress::BasicRedeem([0x01 + i; 20].into()))
            })
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

        assert_eq!(
            sum_staking_coins(&app.storage, app.version - 1),
            Ok(Coin::new(20_0000_0000).unwrap())
        );
    }

    fn check_proof(
        app: &mut App,
        stakings: &[StakedState],
        root_hashes: &[H256],
        staking0: &StakedState,
    ) {
        let reader = KVReader::new(&app.storage);
        let tree = JellyfishMerkleTree::new(&reader);

        // inclusion proof
        for (i, (staking, root_hash)) in stakings.iter().zip(root_hashes.iter()).enumerate() {
            let hash = HashValue::new(staking.key());
            let (mvalue, proof) = tree.get_with_proof(hash, i as u64).unwrap();
            assert_eq!(mvalue, Some(staking.encode().into()));
            proof
                .verify(HashValue::new(*root_hash), hash, mvalue.as_ref())
                .unwrap();
        }
        {
            let hash = HashValue::new(staking0.key());
            let (mvalue, proof) = tree.get_with_proof(hash, stakings.len() as u64).unwrap();
            assert_eq!(mvalue, Some(staking0.encode().into()));
            proof
                .verify(HashValue::new(app.root_hash), hash, mvalue.as_ref())
                .unwrap();
        }

        // exclusion proof
        {
            let hash = HashValue::new(stakings[1].key());
            let (mvalue, proof) = tree.get_with_proof(hash, 0).unwrap();
            assert_eq!(mvalue, None);
            proof
                .verify(HashValue::new(root_hashes[0]), hash, None)
                .unwrap();
        }
    }

    /// Test encoding of jellyfish nodes
    #[test]
    fn check_nodes() {
        let store = create_memorydb(NUM_COLUMNS);
        let reader = KVReader::new(&store);
        let tree = JellyfishMerkleTree::new(&reader);
        let staking1 = StakedState::default(StakedStateAddress::BasicRedeem([0x01; 20].into()));
        let blob1: AccountStateBlob = staking1.encode().into();
        let staking2 = StakedState::default(StakedStateAddress::BasicRedeem([0x02; 20].into()));
        let mut version = 0;

        let (_roots, batch) = tree
            .put_blob_sets(
                vec![vec![(HashValue::new(staking1.key()), blob1.clone())]],
                version,
            )
            .unwrap();

        // a single leaf node.
        assert_eq!(batch.node_batch.len(), 1);
        let (node_key, node) = batch.node_batch.iter().next().unwrap();
        assert_eq!(node_key.encode().unwrap(), vec![0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            node.encode().unwrap(),
            [
                &[0x02][..],           // leaf node
                &staking1.key(),       // key
                blob1.hash().as_ref(), // blob_hash
                &serialize_u64_varint(blob1.as_ref().len() as u64),
                blob1.as_ref(), // blob
            ]
            .concat()
        );
        // write into storage
        flush_kvdb(
            &store,
            batch
                .node_batch
                .into_iter()
                .map(|(key, node)| {
                    (
                        (COL_TRIE_NODE, key.encode().unwrap()),
                        Some(node.encode().unwrap()),
                    )
                })
                .collect::<KVBuffer>(),
        )
        .unwrap();

        version += 1;
        let (_roots, batch) = tree
            .put_blob_sets(
                vec![vec![(HashValue::new(staking2.key()), blob1.clone())]],
                version,
            )
            .unwrap();

        // two leaf nodes and a internal node
        assert_eq!(batch.node_batch.len(), 3);
        // old leaf node is staled since.
        assert_eq!(batch.stale_node_index_batch.len(), 1);
        let mut iter = batch.node_batch.iter();
        let (_internal_key, internal) = iter.next().unwrap();
        let internal = match internal {
            Node::Internal(internal) => internal,
            _ => panic!("incorrect node type"),
        };
        let (leaf_key1, leaf1) = iter.next().unwrap();
        let leaf1 = match leaf1 {
            Node::Leaf(leaf1) => leaf1,
            _ => panic!("incorrect node type"),
        };
        let (leaf_key2, leaf2) = iter.next().unwrap();
        let leaf2 = match leaf2 {
            Node::Leaf(leaf2) => leaf2,
            _ => panic!("incorrect node type"),
        };

        assert_eq!(internal.num_children(), 2);
        assert_eq!(
            internal
                .child(leaf_key1.nibble_path().last().unwrap())
                .unwrap()
                .hash,
            leaf1.hash()
        );
        assert_eq!(
            internal
                .child(leaf_key2.nibble_path().last().unwrap())
                .unwrap()
                .hash,
            leaf2.hash()
        );
        assert!(leaf1.account_key() < leaf2.account_key());
    }

    fn serialize_u64_varint(mut num: u64) -> Vec<u8> {
        let mut binary = vec![];
        for _ in 0..8 {
            let low_bits = num as u8 & 0x7f;
            num >>= 7;
            let more = (num > 0) as u8;
            binary.push(low_bits | more << 7);
            if more == 0 {
                return binary;
            }
        }
        // Last byte is encoded raw; this means there are no bad encodings.
        assert_ne!(num, 0);
        assert!(num <= 0xff);
        binary.push(num as u8);
        binary
    }
}
