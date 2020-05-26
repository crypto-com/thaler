use crate::group::*;
use crate::key::PublicKey;
use crate::keypackage::{self as kp, KeyPackage, MLS10_128_DHKEMP256_AES128GCM_SHA256_P256};
use crate::message::*;
use crate::utils::{decode_option, encode_option, encode_vec_u32, read_vec_u32};
use rustls::internal::msgs::codec::{self, Codec, Reader};

#[derive(Debug, Clone)]
/// spec: draft-ietf-mls-protocol.md#tree-hashes
pub struct ParentNode {
    pub public_key: PublicKey,
    // 0..2^32-1
    pub unmerged_leaves: Vec<u32>,
    // 0..255
    pub parent_hash: Vec<u8>,
}

impl Codec for ParentNode {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public_key.encode(bytes);
        encode_vec_u32(bytes, &self.unmerged_leaves);
        codec::encode_vec_u8(bytes, &self.parent_hash);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let public_key = PublicKey::read(r)?;
        let unmerged_leaves = read_vec_u32(r)?;
        let parent_hash = codec::read_vec_u8(r)?;
        Some(Self {
            public_key,
            unmerged_leaves,
            parent_hash,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#tree-hashes
#[derive(Clone)]
pub enum Node {
    Leaf(Option<KeyPackage>),
    Parent(Option<ParentNode>),
}

impl Node {
    pub fn is_leaf(&self) -> bool {
        matches!(self, Node::Leaf(_))
    }

    pub fn is_empty_leaf(&self) -> bool {
        matches!(self, Node::Leaf(None))
    }
}

#[derive(Debug)]
/// spec: draft-ietf-mls-protocol.md#tree-hashes
pub struct ParentNodeHashInput {
    pub node_index: u32,
    pub parent_node: Option<ParentNode>,
    pub left_hash: Vec<u8>,
    pub right_hash: Vec<u8>,
}

impl Codec for ParentNodeHashInput {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.node_index.encode(bytes);
        encode_option(bytes, &self.parent_node);
        codec::encode_vec_u8(bytes, &self.left_hash);
        codec::encode_vec_u8(bytes, &self.right_hash);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let node_index = u32::read(r)?;
        let parent_node: Option<ParentNode> = decode_option(r)?;
        let left_hash = codec::read_vec_u8(r)?;
        let right_hash = codec::read_vec_u8(r)?;

        Some(Self {
            node_index,
            parent_node,
            left_hash,
            right_hash,
        })
    }
}

#[derive(Debug)]
/// spec: draft-ietf-mls-protocol.md#tree-hashes
pub struct LeafNodeHashInput {
    pub node_index: u32,
    pub key_package: Option<KeyPackage>,
}

impl Codec for LeafNodeHashInput {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.node_index.encode(bytes);
        encode_option(bytes, &self.key_package);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let node_index = u32::read(r)?;
        let key_package: Option<KeyPackage> = decode_option(r)?;

        Some(Self {
            node_index,
            key_package,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#tree-math
/// TODO: https://github.com/mlswg/mls-protocol/pull/327/files
#[derive(Clone)]
pub struct Tree {
    /// all tree nodes stored in a vector
    pub nodes: Vec<Node>,
    /// the used ciphersuite (for hashing etc.)
    /// TODO: unify with keypackage one
    pub cs: CipherSuite,
    /// position of the participant in the tree
    /// TODO: leaf vs node position?
    pub my_pos: usize,
}

/// The level of a node in the tree.  Leaves are level 0, their
/// parents are level 1, etc.  If a node's children are at different
/// level, then its level is the max level of its children plus one.
#[inline]
fn level(x: usize) -> usize {
    if (x & 0x01) == 0 {
        return 0;
    }
    let mut k = 0;
    while ((x >> k) & 0x01) == 1 {
        k += 1;
    }
    k
}

/// The number of nodes needed to represent a tree with n leaves
#[inline]
fn node_width(n: usize) -> usize {
    2 * (n - 1) + 1
}

/// The left child of an intermediate node.  Note that because the
/// tree is left-balanced, there is no dependency on the size of the
/// tree.  The child of a leaf node is itself.
#[inline]
fn left(x: usize) -> usize {
    let k = level(x);
    if k == 0 {
        return x;
    }
    x ^ (0x01 << (k - 1))
}

/// The right child of an intermediate node.  Depends on the size of
/// the tree because the straightforward calculation can take you
/// beyond the edge of the tree.  The child of a leaf node is itself.
#[inline]
fn right(x: usize, n: usize) -> usize {
    let k = level(x);
    if k == 0 {
        return x;
    }
    let mut r = x ^ (0x03 << (k - 1));
    while r >= node_width(n) {
        r = left(r);
    }
    r
}

/// The index of the root node of a tree with n leaves
#[inline]
fn root(n: usize) -> usize {
    let w = node_width(n);
    (1usize << log2(w)) - 1
}

/// The largest power of 2 less than n.  Equivalent to:
///  int(math.floor(math.log(x, 2)))
#[inline]
fn log2(x: usize) -> usize {
    if x == 0 {
        return 0;
    }

    let mut k = 0;
    while (x >> k) > 0 {
        k += 1
    }
    k - 1
}

/// The immediate parent of a node.  May be beyond the right edge of
/// the tree.
#[inline]
fn parent_step(x: usize) -> usize {
    let k = level(x);
    let b = (x >> (k + 1)) & 0x01;
    (x | (1 << k)) ^ (b << (k + 1))
}

/// The parent of a node.  As with the right child calculation, have
/// to walk back until the parent is within the range of the tree.
#[inline]
fn parent(x: usize, n: usize) -> usize {
    if x == root(n) {
        return x;
    }
    let mut p = parent_step(x);
    while p >= node_width(n) {
        p = parent_step(p)
    }
    p
}

/// The direct path of a node, ordered from the root
/// down, including the root
#[inline]
fn direct_path(node_pos: usize, n: usize) -> Vec<usize> {
    let mut d = Vec::new();
    let mut p = parent(node_pos, n);
    let r = root(n);
    while p != r {
        d.push(p);
        p = parent(p, n);
    }
    if node_pos != r {
        d.push(r);
    }
    d
}

impl Tree {
    fn get_free_leaf_or_extend(&mut self) -> usize {
        match self.nodes.iter().position(|n| n.is_empty_leaf()) {
            Some(i) => i,
            None => {
                self.nodes.push(Node::Parent(None));
                self.nodes.push(Node::Leaf(None));
                self.nodes.len() - 1
            }
        }
    }

    pub fn update(
        &mut self,
        add_proposals: &[MLSPlaintext],
        update_proposals: &[MLSPlaintext],
        remove_proposals: &[MLSPlaintext],
    ) {
        for _update in update_proposals.iter() {
            // FIXME
        }
        for _remove in remove_proposals.iter() {
            // FIXME
        }
        for add in add_proposals.iter() {
            // position to add
            // "If necessary, extend the tree to the right until it has at least index + 1 leaves"
            let position = self.get_free_leaf_or_extend();
            let leafs = self.leaf_len();
            let dirpath = direct_path(position, leafs);
            for d in dirpath.iter() {
                let node = &mut self.nodes[*d];
                if let Node::Parent(Some(ref mut np)) = node {
                    // "For each non-blank intermediate node along the
                    // path from the leaf at position index to the root,
                    // add index to the unmerged_leaves list for the node."
                    let du32 = *d as u32;
                    if !np.unmerged_leaves.contains(&du32) {
                        np.unmerged_leaves.push(du32);
                    }
                }
            }
            // "Set the leaf node in the tree at position index to a new node containing the public key
            // from the KeyPackage in the Add, as well as the credential under which the KeyPackage was signed"
            let leaf_node = Node::Leaf(add.get_add_keypackage());
            self.nodes[position] = leaf_node;
        }
    }

    fn node_hash(&self, index: usize) -> Vec<u8> {
        let node = &self.nodes[index];
        match node {
            Node::Leaf(kp) => {
                let mut inp = Vec::new();
                LeafNodeHashInput {
                    node_index: index as u32,
                    key_package: kp.clone(),
                }
                .encode(&mut inp);
                self.cs.hash(&inp)
            }
            Node::Parent(pn) => {
                let left_index = left(index);
                let left_hash = self.node_hash(left_index);
                let right_index = right(index, self.nodes.len());
                let right_hash = self.node_hash(right_index);
                let mut inp = Vec::new();
                ParentNodeHashInput {
                    node_index: index as u32,
                    parent_node: pn.clone(),
                    left_hash,
                    right_hash,
                }
                .encode(&mut inp);
                self.cs.hash(&inp)
            }
        }
    }

    fn leaf_len(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_leaf()).count()
    }

    pub fn compute_tree_hash(&self) -> Vec<u8> {
        let root_index = root(self.leaf_len());
        self.node_hash(root_index)
    }

    pub fn init(creator_kp: KeyPackage) -> Result<Self, kp::Error> {
        let cs = match creator_kp.payload.cipher_suite {
            MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Ok(CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256)
            }
            _ => Err(kp::Error::UnsupportedCipherSuite(
                creator_kp.payload.cipher_suite,
            )),
        }?;
        Ok(Self {
            nodes: vec![Node::Leaf(Some(creator_kp))],
            cs,
            my_pos: 0,
        })
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test_tree_math() {
        use super::{direct_path, left, level, log2, parent, right, root};
        // Precomputed answers for the tree on eleven elements
        // adapted from https://github.com/cisco/go-mls/blob/master/tree-math_test.go
        let a_root = vec![
            0x00, 0x01, 0x03, 0x03, 0x07, 0x07, 0x07, 0x07, 0x0f, 0x0f, 0x0f,
        ];
        let a_log2 = vec![
            0x00, 0x00, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04,
        ];
        let a_level = vec![
            0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00,
        ];
        let a_left = vec![
            0x00, 0x00, 0x02, 0x01, 0x04, 0x04, 0x06, 0x03, 0x08, 0x08, 0x0a, 0x09, 0x0c, 0x0c,
            0x0e, 0x07, 0x10, 0x10, 0x12, 0x11, 0x14,
        ];
        let a_right = vec![
            0x00, 0x02, 0x02, 0x05, 0x04, 0x06, 0x06, 0x0b, 0x08, 0x0a, 0x0a, 0x0d, 0x0c, 0x0e,
            0x0e, 0x13, 0x10, 0x12, 0x12, 0x14, 0x14,
        ];
        let a_parent = vec![
            0x01, 0x03, 0x01, 0x07, 0x05, 0x03, 0x05, 0x0f, 0x09, 0x0b, 0x09, 0x07, 0x0d, 0x0b,
            0x0d, 0x0f, 0x11, 0x13, 0x11, 0x0f, 0x13,
        ];
        let a_dirpath = [
            vec![0x01, 0x03, 0x07, 0x0f],
            vec![0x03, 0x07, 0x0f],
            vec![0x01, 0x03, 0x07, 0x0f],
            vec![0x07, 0x0f],
            vec![0x05, 0x03, 0x07, 0x0f],
            vec![0x03, 0x07, 0x0f],
            vec![0x05, 0x03, 0x07, 0x0f],
            vec![0x0f],
            vec![0x09, 0x0b, 0x07, 0x0f],
            vec![0x0b, 0x07, 0x0f],
            vec![0x09, 0x0b, 0x07, 0x0f],
            vec![0x07, 0x0f],
            vec![0x0d, 0x0b, 0x07, 0x0f],
            vec![0x0b, 0x07, 0x0f],
            vec![0x0d, 0x0b, 0x07, 0x0f],
            vec![],
            vec![0x11, 0x13, 0x0f],
            vec![0x13, 0x0f],
            vec![0x11, 0x13, 0x0f],
            vec![0x0f],
            vec![0x13, 0x0f],
        ];
        let a_n = 0x0b;
        for n in 1..a_n {
            assert_eq!(root(n), a_root[n - 1])
        }
        for i in 0x00..0x14 {
            assert_eq!(a_log2[i], log2(i));
            assert_eq!(a_level[i], level(i));
            assert_eq!(a_left[i], left(i));
            assert_eq!(a_right[i], right(i, a_n));
            assert_eq!(a_parent[i], parent(i, a_n));
            assert_eq!(a_dirpath[i], direct_path(i, a_n));
        }
    }
}
