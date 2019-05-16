use crate::common::{H256, HASH_SIZE_256};
use crate::tx::data::{txid_hash, TxId};
use parity_codec_derive::{Encode, Decode};

/// hash digest
pub type Hash256 = H256;

/// Tree is either empty or has some nodes
#[derive(Encode, Decode)]
pub enum MerkleTree {
    Empty,
    Tree(usize, MerkleNode),
}

/// Node is either an inner node (branch) or a leaf
#[derive(Encode, Decode)]
pub enum MerkleNode {
    Branch(Hash256, Box<MerkleNode>, Box<MerkleNode>),
    Leaf(Hash256),
}

// txid_hash(&vec![])
const EMPTY_HASH: [u8; HASH_SIZE_256] = [
    105, 33, 122, 48, 121, 144, 128, 148, 225, 17, 33, 208, 66, 53, 74, 124, 31, 85, 182, 72, 44,
    161, 165, 30, 27, 37, 13, 253, 30, 208, 238, 249,
];

impl MerkleTree {
    /// create a new tree from a vector of transaction IDs
    pub fn new(xs: &[TxId]) -> Self {
        if xs.is_empty() {
            return MerkleTree::Empty;
        }

        MerkleTree::Tree(xs.len(), MerkleNode::make_tree(&xs[..]))
    }

    /// returns the merkle root == hash of the root node in a non-empty tree
    pub fn get_root_hash(&self) -> Hash256 {
        match self {
            MerkleTree::Empty => EMPTY_HASH.into(),
            MerkleTree::Tree(_, node) => *node.get_root_hash(),
        }
    }
}

impl MerkleNode {
    /// constructs a merkle tree from a vector / slice of TX ids:
    /// Leafs => TxId
    /// Branches => txid_hash(1 || left_hash || right_hash)
    fn make_tree(xs: &[TxId]) -> Self {
        if xs.is_empty() {
            panic!("make_tree applied to empty list")
        } else if xs.len() == 1 {
            // TODO: should this be prefixed by vec![0u8] and re-hashed?
            MerkleNode::Leaf(xs[0])
        } else {
            let i = xs.len().checked_next_power_of_two().unwrap() >> 1;
            let a = MerkleNode::make_tree(&xs[0..i]);
            let b = MerkleNode::make_tree(&xs[i..]);
            let mut bs = vec![1u8];
            bs.extend(a.get_root_hash());
            bs.extend(b.get_root_hash());
            MerkleNode::Branch(txid_hash(&bs), Box::new(a), Box::new(b))
        }
    }

    /// returns the hash at that node
    pub fn get_root_hash(&self) -> &Hash256 {
        match self {
            MerkleNode::Branch(hash, _, _) => hash,
            MerkleNode::Leaf(hash) => hash,
        }
    }
}
