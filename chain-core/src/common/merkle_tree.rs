use std::prelude::v1::{Box, Vec};
use std::vec::IntoIter;

use super::H256;
use blake3::Hash;
use parity_scale_codec::{Decode, Encode};

/// Hash of leaf node with empty slice `hash_leaf(&[])`
const EMPTY_HASH: H256 = [
    45, 58, 222, 223, 241, 27, 97, 241, 76, 136, 110, 53, 175, 160, 54, 115, 109, 205, 135, 167,
    77, 39, 181, 193, 81, 2, 37, 208, 245, 146, 226, 19,
];

/// Represents inner tree structure of Merkle Tree
#[derive(Debug, Encode, Decode)]
pub enum Tree<T> {
    /// Empty Node
    Empty,
    /// Leaf Node
    Leaf { hash: H256, value: T },
    /// Middle Node
    Node {
        hash: H256,
        left: Box<Tree<T>>,
        right: Box<Tree<T>>,
    },
}

impl<T> Tree<T> {
    /// Creates a tree with one empty node
    #[inline]
    pub fn empty() -> Self {
        Tree::Empty
    }

    /// Creates a tree with one leaf node
    #[inline]
    pub fn leaf(value: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Tree::Leaf {
            hash: hash_leaf(&value),
            value,
        }
    }

    /// Creates a tree with given left and right sub-trees
    #[inline]
    pub fn node(left: Box<Tree<T>>, right: Box<Tree<T>>) -> Self {
        Tree::Node {
            hash: hash_intermediate(&left.hash(), &right.hash()),
            left,
            right,
        }
    }

    /// Returns hash of root node of tree
    #[inline]
    pub fn hash(&self) -> H256 {
        match self {
            Tree::Empty => EMPTY_HASH,
            Tree::Leaf { hash, .. } => *hash,
            Tree::Node { hash, .. } => *hash,
        }
    }

    /// Generates merkle path for given value. Returns `None` if given value is not present in tree.
    /// Uses depth first search (DFS) to find value in tree
    fn generate_path(&self, value: &T) -> Option<Path>
    where
        T: AsRef<[u8]> + Clone,
    {
        match self {
            Tree::Empty => None,
            Tree::Leaf {
                hash: node_hash, ..
            } => {
                if &hash_leaf(value) == node_hash {
                    Some(Path { nodes: vec![] })
                } else {
                    None
                }
            }
            Tree::Node {
                hash: node_hash,
                left,
                right,
            } => left.generate_path(value).map_or_else(
                || {
                    right.generate_path(value).map(|mut path| {
                        path.nodes.push(PathNode {
                            node_hash: *node_hash,
                            child_hash: left.hash(),
                            hash_side: Side::Left,
                        });
                        path
                    })
                },
                |mut path| {
                    path.nodes.push(PathNode {
                        node_hash: *node_hash,
                        child_hash: right.hash(),
                        hash_side: Side::Right,
                    });
                    Some(path)
                },
            ),
        }
    }
}

/// Merkle path for inclusion proof
///
/// ```plain
///          node_hash1, Left
///              |
///           +--+--+
///           |     |
///  child_hash1  node_hash0, Right
///                 |
///              +--+--+
///              |     |
///        leaf_hash   child_hash0
/// ```
///
/// Above merkle path is represented as:
///
/// ```plain
/// Path {
///   nodes: [ PathNode {
///     node_hash: node_hash0,
///     child_hash: child_hash0,
///     hash_side: Right
///   }, PathNode {
///     node_hash: node_hash1,
///     child_hash: child_hash1,
///     hash_side: Left
///   } ]
/// }
/// ```
///
/// leaf_hash is computed from the value in the Proof

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub enum Side {
    Left,
    Right,
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PathNode {
    node_hash: H256,
    child_hash: H256, // hash of left child unless reversed
    hash_side: Side,  // the side of hash child
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct Path {
    nodes: Vec<PathNode>, // order from inner node to outer node
}

impl Path {
    fn hash(&self) -> Option<&H256> {
        match self.nodes.last() {
            None => None,
            Some(node) => Some(&node.node_hash),
        }
    }

    fn verify(&self, leaf_hash: &H256) -> bool {
        for i in (0..self.nodes.len()).rev() {
            let node = &self.nodes[i];

            let ref_hash = if i == 0 {
                leaf_hash
            } else {
                &self.nodes[i - 1].node_hash
            };

            let calced_hash = Hash::from(if Side::Left == node.hash_side {
                hash_intermediate(&node.child_hash, &ref_hash)
            } else {
                hash_intermediate(&ref_hash, &node.child_hash)
            });

            if calced_hash != Hash::from(node.node_hash) {
                return false;
            }
        }
        true
    }
}

/// Inclusion proof of a value
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct Proof<T> {
    path: Path,
    value: T,
}

impl<T> Proof<T> {
    /// Verifies inclusion proof in given merkle tree
    #[inline]
    pub fn verify(&self, root_hash: &H256) -> bool
    where
        T: AsRef<[u8]>,
    {
        let expected_root = Hash::from(*root_hash);
        let leaf_hash = hash_leaf(self.value.as_ref());
        let actual_root_hash = Hash::from(*self.path.hash().unwrap_or(&leaf_hash));
        self.path.verify(&leaf_hash) && expected_root == actual_root_hash
    }

    /// Returns a borrow of value contained in this proof
    #[inline]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Returns root hash of this proof
    #[inline]
    pub fn root_hash(&self) -> H256
    where
        T: AsRef<[u8]>,
    {
        match self.path.hash() {
            None => hash_leaf(self.value.as_ref()),
            Some(v) => *v,
        }
    }
}

/// Merkle tree with values of type `T` and support for inclusion proofs
///
/// # Usage
///
/// ## Creating a `MerkleTree`
/// ```
/// # use chain_core::common::MerkleTree;
/// #
/// let values = vec!["one", "two", "three", "four"];
/// let tree = MerkleTree::new(values);
/// ```
///
/// ## Generating inclusion proof
/// ```
/// # use chain_core::common::MerkleTree;
/// #
/// # let values = vec!["one", "two", "three", "four"];
/// # let tree = MerkleTree::new(values);
/// #
/// let one_proof = tree.generate_proof("one").expect("Unable to generate inclusion proof");
/// ```
///
/// ## Verifying inclusion proof
/// ```
/// # use chain_core::common::MerkleTree;
/// #
/// # let values = vec!["one", "two", "three", "four"];
/// # let tree = MerkleTree::new(values);
/// #
/// # let one_proof = tree.generate_proof("one").expect("Unable to generate inclusion proof");
/// assert!(one_proof.verify(&tree.root_hash()));
/// ```
#[derive(Debug, Encode, Decode)]
pub struct MerkleTree<T> {
    tree: Tree<T>,
    len: u64,
    height: u64,
}

impl<T> MerkleTree<T> {
    /// Creates an empty merkle tree
    #[inline]
    pub fn empty() -> Self {
        Self {
            tree: Tree::empty(),
            len: 0,
            height: 0,
        }
    }

    /// Creates a new merkle tree with given values as leaves
    pub fn new(values: Vec<T>) -> Self
    where
        T: AsRef<[u8]>,
    {
        if values.is_empty() {
            Self::empty()
        } else {
            let len = values.len();
            let mut trees = values.into_iter().map(Tree::leaf).collect::<Vec<Tree<T>>>();
            let mut height = 0;

            while trees.len() > 1 {
                trees = PairIter::from(trees.into_iter())
                    .map(|(left, right)| match right {
                        None => left,
                        Some(right) => Tree::node(Box::new(left), Box::new(right)),
                    })
                    .collect::<Vec<Tree<T>>>();
                height += 1;
            }

            Self {
                tree: trees.remove(0),
                len: len as u64,
                height: height as u64,
            }
        }
    }

    /// Returns root hash of merkle tree
    #[inline]
    pub fn root_hash(&self) -> H256 {
        self.tree.hash()
    }

    /// Returns height of merkle tree
    #[inline]
    pub fn height(&self) -> usize {
        self.height as usize
    }

    /// Returns the number of leaf nodes in merkle tree
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` if current merkle tree is empty, `false` otherwise
    #[inline]
    pub fn is_empty(&self) -> bool {
        0 == self.len
    }

    /// Generates inclusion proof for given value. Returns `None` if given value is not present in merkle tree
    pub fn generate_proof(&self, value: T) -> Option<Proof<T>>
    where
        T: AsRef<[u8]> + Clone,
    {
        self.generate_path(&value).map(|path| {
            if let Some(p) = path.hash() {
                assert_eq!(&self.root_hash(), p);
            }
            Proof { path, value }
        })
    }

    /// Generates merkle path for given value. Returns `None` if given value is not present in merkle tree
    #[inline]
    fn generate_path(&self, value: &T) -> Option<Path>
    where
        T: AsRef<[u8]> + Clone,
    {
        self.tree.generate_path(value)
    }
}

#[inline]
fn hash_leaf<T: AsRef<[u8]>>(value: T) -> H256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x00]);
    hasher.update(value.as_ref());
    hasher.finalize().into()
}

#[inline]
fn hash_intermediate(left: &H256, right: &H256) -> H256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// An iterator which iterates over pair of values
pub struct PairIter<T> {
    inner: IntoIter<T>,
}

impl<T> From<IntoIter<T>> for PairIter<T> {
    #[inline]
    fn from(inner: IntoIter<T>) -> Self {
        Self { inner }
    }
}

impl<T> Iterator for PairIter<T> {
    type Item = (T, Option<T>);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|next| (next, self.inner.next()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_empty_hash() {
        let values: [u8; 0] = [];
        assert_eq!(EMPTY_HASH, hash_leaf(&values));
    }

    #[test]
    fn check_empty() {
        let values: Vec<H256> = vec![];
        let tree = MerkleTree::new(values);

        assert!(tree.is_empty());
        assert_eq!(EMPTY_HASH, tree.root_hash());
        assert_eq!(0, tree.height());
        assert_eq!(0, tree.len());
        assert_eq!(None, tree.generate_proof([0u8; 32]));
    }

    #[test]
    fn check_vec_1() {
        let values = vec!["one"];
        let tree = MerkleTree::new(values);

        assert_eq!(hash_leaf("one"), tree.root_hash());
        assert_eq!(0, tree.height());
        assert_eq!(1, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));
        assert!(tree
            .generate_proof("one")
            .unwrap()
            .verify(&tree.root_hash()));
    }

    #[test]
    fn check_vec_2() {
        let values = vec!["one", "two"];
        let hashes = values
            .iter()
            .map(|value| hash_leaf(value))
            .collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let root_hash = hash_intermediate(&hashes[0], &hashes[1]);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(1, tree.height());
        assert_eq!(2, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree
            .generate_proof("one")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("two")
            .unwrap()
            .verify(&tree.root_hash()));
    }

    #[test]
    fn check_vec_3() {
        let values = vec!["one", "two", "three"];
        let hashes = values
            .iter()
            .map(|value| hash_leaf(value))
            .collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = hash_intermediate(&hashes[0], &hashes[1]);
        let root_hash = hash_intermediate(&h01, &hashes[2]);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(2, tree.height());
        assert_eq!(3, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree
            .generate_proof("one")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("two")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(&tree.root_hash()));
    }

    #[test]
    fn check_vec_4() {
        let values = vec!["one", "two", "three", "four"];
        let hashes = values
            .iter()
            .map(|value| hash_leaf(value))
            .collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = hash_intermediate(&hashes[0], &hashes[1]);
        let h23 = hash_intermediate(&hashes[2], &hashes[3]);

        let root_hash = hash_intermediate(&h01, &h23);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(2, tree.height());
        assert_eq!(4, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree
            .generate_proof("one")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("two")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(&tree.root_hash()));
    }

    #[test]
    fn check_vec_5() {
        let values = vec!["one", "two", "three", "four", "five"];
        let hashes = values
            .iter()
            .map(|value| hash_leaf(value))
            .collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = hash_intermediate(&hashes[0], &hashes[1]);
        let h23 = hash_intermediate(&hashes[2], &hashes[3]);
        let h4 = hash_intermediate(&h01, &h23);

        let root_hash = hash_intermediate(&h4, &hashes[4]);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(3, tree.height());
        assert_eq!(5, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree
            .generate_proof("one")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("two")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("five")
            .unwrap()
            .verify(&tree.root_hash()));
    }

    #[test]
    fn check_vec_6() {
        let values = vec!["one", "two", "three", "four", "five", "six"];
        let hashes = values
            .iter()
            .map(|value| hash_leaf(value))
            .collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = hash_intermediate(&hashes[0], &hashes[1]);
        let h23 = hash_intermediate(&hashes[2], &hashes[3]);
        let h45 = hash_intermediate(&hashes[4], &hashes[5]);

        let h6 = hash_intermediate(&h01, &h23);

        let root_hash = hash_intermediate(&h6, &h45);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(3, tree.height());
        assert_eq!(6, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree
            .generate_proof("one")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("two")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(&tree.root_hash()));
        &assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("five")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("six")
            .unwrap()
            .verify(&tree.root_hash()));
    }

    #[test]
    fn check_vec_7() {
        let values = vec!["one", "two", "three", "four", "five", "six", "seven"];
        let hashes = values
            .iter()
            .map(|value| hash_leaf(value))
            .collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = hash_intermediate(&hashes[0], &hashes[1]);
        let h23 = hash_intermediate(&hashes[2], &hashes[3]);
        let h45 = hash_intermediate(&hashes[4], &hashes[5]);

        let h6 = hash_intermediate(&h01, &h23);
        let h7 = hash_intermediate(&h45, &hashes[6]);

        let root_hash = hash_intermediate(&h6, &h7);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(3, tree.height());
        assert_eq!(7, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree
            .generate_proof("one")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("two")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("five")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("six")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("seven")
            .unwrap()
            .verify(&tree.root_hash()));
    }

    #[test]
    fn check_vec_8() {
        let values = vec![
            "one", "two", "three", "four", "five", "six", "seven", "eight",
        ];
        let hashes = values
            .iter()
            .map(|value| hash_leaf(value))
            .collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = hash_intermediate(&hashes[0], &hashes[1]);
        let h23 = hash_intermediate(&hashes[2], &hashes[3]);
        let h45 = hash_intermediate(&hashes[4], &hashes[5]);
        let h67 = hash_intermediate(&hashes[6], &hashes[7]);

        let h8 = hash_intermediate(&h01, &h23);
        let h9 = hash_intermediate(&h45, &h67);

        let root_hash = hash_intermediate(&h8, &h9);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(3, tree.height());
        assert_eq!(8, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree
            .generate_proof("one")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("two")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(&tree
            .generate_proof("three")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(&tree
            .generate_proof("four")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("five")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("six")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("seven")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("eight")
            .unwrap()
            .verify(&tree.root_hash()));
    }

    #[test]
    fn check_vec_9() {
        let values = vec![
            "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
        ];
        let hashes = values
            .iter()
            .map(|value| hash_leaf(value))
            .collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = hash_intermediate(&hashes[0], &hashes[1]);
        let h23 = hash_intermediate(&hashes[2], &hashes[3]);
        let h45 = hash_intermediate(&hashes[4], &hashes[5]);
        let h67 = hash_intermediate(&hashes[6], &hashes[7]);

        let h8 = hash_intermediate(&h01, &h23);
        let h9 = hash_intermediate(&h45, &h67);
        let h10 = hash_intermediate(&h8, &h9);

        let root_hash = hash_intermediate(&h10, &hashes[8]);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(4, tree.height());
        assert_eq!(9, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree
            .generate_proof("one")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("two")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("five")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("six")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("seven")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("eight")
            .unwrap()
            .verify(&tree.root_hash()));
        assert!(tree
            .generate_proof("nine")
            .unwrap()
            .verify(&tree.root_hash()));
    }

    #[test]
    fn check_wrong_proof() {
        let values = vec!["one", "two", "three", "four"];
        let tree = MerkleTree::new(values);

        let new_values = vec!["one", "two", "three", "five"];
        let new_tree = MerkleTree::new(new_values);

        assert!(!tree
            .generate_proof("one")
            .unwrap()
            .verify(&new_tree.root_hash()));
    }

    #[test]
    fn check_wrong_leaf_value() {
        let values = vec!["one", "two", "three", "four"];
        let tree = MerkleTree::new(values);

        let mut proof = tree.generate_proof("one").unwrap();
        assert!(proof.verify(&tree.root_hash()));

        // Intentionally change the value in proof
        proof.value = "two";
        assert!(!proof.verify(&tree.root_hash()));
    }
}
