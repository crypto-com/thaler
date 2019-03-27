use crate::common::{H256, HASH_SIZE_256};
use crate::tx::data::{txid_hash, TxId};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

/// hash digest
pub type Hash256 = H256;

/// Tree is either empty or has some nodes
pub enum MerkleTree {
    Empty,
    Tree(usize, MerkleNode),
}

/// TODO: better encoding
impl Encodable for MerkleTree {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            MerkleTree::Empty => {
                s.begin_list(1).append(&0u8);
            }
            MerkleTree::Tree(size, node) => {
                s.begin_list(3).append(&1u8).append(size).append(node);
            }
        }
    }
}

impl Decodable for MerkleTree {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let item_count = rlp.item_count()?;
        if !(item_count == 1 || item_count == 3) {
            return Err(DecoderError::Custom("Cannot decode a merkle tree"));
        }
        let type_tag: u8 = rlp.val_at(0)?;
        match (type_tag, item_count) {
            (0, 1) => Ok(MerkleTree::Empty),
            (1, 3) => {
                let size: usize = rlp.val_at(1)?;
                let node: MerkleNode = rlp.val_at(2)?;
                Ok(MerkleTree::Tree(size, node))
            }
            _ => Err(DecoderError::Custom("Unknown merkle tree type")),
        }
    }
}

/// Node is either an inner node (branch) or a leaf
pub enum MerkleNode {
    Branch(Hash256, Box<MerkleNode>, Box<MerkleNode>),
    Leaf(Hash256),
}

/// TODO: better encoding
impl Encodable for MerkleNode {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            MerkleNode::Leaf(h) => {
                s.begin_list(2).append(&0u8).append(h);
            }
            MerkleNode::Branch(h, l, r) => {
                s.begin_list(4)
                    .append(&1u8)
                    .append(h)
                    .append_list(&l.rlp_bytes())
                    .append_list(&r.rlp_bytes());
            }
        }
    }
}

impl Decodable for MerkleNode {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let item_count = rlp.item_count()?;
        if !(item_count == 2 || item_count == 4) {
            return Err(DecoderError::Custom("Cannot decode a merkle node"));
        }
        let type_tag: u8 = rlp.val_at(0)?;
        match (type_tag, item_count) {
            (0, 2) => {
                let h: Hash256 = rlp.val_at(1)?;
                Ok(MerkleNode::Leaf(h))
            }
            (1, 4) => {
                let h: Hash256 = rlp.val_at(1)?;
                let l: MerkleNode = rlp.val_at(2)?;
                let r: MerkleNode = rlp.val_at(3)?;
                Ok(MerkleNode::Branch(h, Box::new(l), Box::new(r)))
            }
            _ => Err(DecoderError::Custom("Unknown merkle node type")),
        }
    }
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
            MerkleNode::Leaf(xs[0])
        } else {
            let i = xs.len().checked_next_power_of_two().unwrap() >> 1;
            let a = MerkleNode::make_tree(&xs[0..i]);
            let b = MerkleNode::make_tree(&xs[i..]);
            let mut bs = vec![1u8];
            bs.extend(a.get_root_hash().as_bytes().iter());
            bs.extend(b.get_root_hash().as_bytes().iter());
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
