use anyhow::{ensure, Result};
use jellyfish_merkle::{node_type::Node, HashValue, JellyfishMerkleTree};
use parity_scale_codec::Encode;

use chain_core::common::H256;
use chain_core::state::account::{StakedState, StakedStateAddress};
use chain_storage::buffer::{MemStore, StoreKV};
use chain_storage::jellyfish::{KVReader, Version};
use chain_storage::COL_TRIE_NODE;

const HELP: &str = "jellyfish_nodes versions stakings";

/// Put stakings into the merkle tree, remove stale nodes immediatelly
fn put_stakings<'a, S: StoreKV>(
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
        storage.delete((COL_TRIE_NODE, key.node_key.encode()?));
    }
    Ok(*root_hashes[0].as_ref())
}

fn avg_fill_rate(store: &MemStore<(u32, Vec<u8>), Vec<u8>>) -> f64 {
    let mut full = 0;
    let mut num = 0;
    for v in store.0.values() {
        let (full_, num_) = match Node::decode(&v).unwrap() {
            Node::Internal(internal) => (16, internal.num_children()),
            _ => (0, 0),
        };
        full += full_;
        num += num_;
    }
    num as f64 / full as f64
}

fn main() {
    let mut args = std::env::args().skip(1);
    let version: u64 = match args.next() {
        Some(arg) => arg.parse().unwrap(),
        None => {
            println!("{}", HELP);
            return;
        }
    };
    let num_stakings: u64 = match args.next() {
        Some(arg) => arg.parse().unwrap(),
        None => {
            println!("{}", HELP);
            return;
        }
    };

    let mut store = MemStore::new();
    for version in 0..version {
        let stakings = (0..num_stakings)
            .map(|i| {
                let mut seed = [0; 20];
                seed[..8].clone_from_slice(&version.to_le_bytes());
                seed[8..16].clone_from_slice(&i.to_le_bytes());
                StakedState::default(StakedStateAddress::BasicRedeem(seed.into()))
            })
            .collect::<Vec<_>>();
        put_stakings(&mut store, version as Version, stakings.iter())
            .expect("jellyfish error with in memory storage");

        let leafs = ((version + 1) * num_stakings) as usize;
        let internals = store.0.len() - leafs;
        println!(
            "internal/leaf: {} / {} = {}",
            internals,
            leafs,
            (internals as f64 / leafs as f64)
        );
        println!("internal avg fill rate: {}", avg_fill_rate(&store));
    }
}
