use std::vec::IntoIter;

use blake2::Blake2s;

use super::{hash256, H256, H512, HASH_SIZE_256};

// hash(&vec![])
const EMPTY_HASH: H256 = [
    105, 33, 122, 48, 121, 144, 128, 148, 225, 17, 33, 208, 66, 53, 74, 124, 31, 85, 182, 72, 44,
    161, 165, 30, 27, 37, 13, 253, 30, 208, 238, 249,
];

/// Represents inner tree structure of Merkle Tree
#[derive(Debug)]
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
            hash: hash(&value),
            value,
        }
    }

    /// Creates a tree with given left and right sub-trees
    #[inline]
    pub fn node(left: Box<Tree<T>>, right: Box<Tree<T>>) -> Self {
        Tree::Node {
            hash: combined_hash(&left.hash(), &right.hash()),
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
    fn generate_path(&self, value: T) -> Option<Path>
    where
        T: AsRef<[u8]> + Clone,
    {
        match self {
            Tree::Empty => None,
            Tree::Leaf {
                hash: node_hash, ..
            } => {
                if &hash(value) == node_hash {
                    Some(Path {
                        node_hash: *node_hash,
                        sibling: None,
                        sub_path: None,
                    })
                } else {
                    None
                }
            }
            Tree::Node { hash, left, right } => match left.generate_path(value.clone()) {
                None => right.generate_path(value).map(|mut path| {
                    path.sibling = Some(Sibling::Left(left.hash()));

                    Path {
                        node_hash: *hash,
                        sibling: None,
                        sub_path: Some(Box::new(path)),
                    }
                }),
                Some(mut path) => {
                    path.sibling = Some(Sibling::Right(right.hash()));

                    Some(Path {
                        node_hash: *hash,
                        sibling: None,
                        sub_path: Some(Box::new(path)),
                    })
                }
            },
        }
    }
}

/// Sibling's hash
#[derive(Debug, PartialEq)]
pub enum Sibling {
    Left(H256),
    Right(H256),
}

/// Merkle path for inclusion proof
#[derive(Debug, PartialEq)]
pub struct Path {
    node_hash: H256,
    sibling: Option<Sibling>,
    sub_path: Option<Box<Path>>,
}

impl Path {
    /// Verifies inclusion of given hash in current path
    fn verify(&self) -> bool {
        match self.calculate_hash() {
            None => false,
            Some(path_hash) => path_hash == self.node_hash,
        }
    }

    /// Calculates hash of a path
    fn calculate_hash(&self) -> Option<H256> {
        match self.sub_path {
            None => match self.sibling {
                None => Some(self.node_hash),
                Some(ref sibling) => match sibling {
                    Sibling::Left(sibling_hash) => {
                        Some(combined_hash(sibling_hash, &self.node_hash))
                    }
                    Sibling::Right(sibling_hash) => {
                        Some(combined_hash(&self.node_hash, sibling_hash))
                    }
                },
            },
            Some(ref sub_path) => match self.sibling {
                None => sub_path.calculate_hash(),
                Some(ref sibling) => sub_path.calculate_hash().map(|sub_hash| match sibling {
                    Sibling::Left(sibling_hash) => combined_hash(sibling_hash, &sub_hash),
                    Sibling::Right(sibling_hash) => combined_hash(&sub_hash, sibling_hash),
                }),
            },
        }
    }
}

/// Inclusion proof of a value
#[derive(Debug, PartialEq)]
pub struct Proof<T> {
    root_hash: H256,
    path: Path,
    value: T,
}

impl<T> Proof<T> {
    /// Verifies inclusion proof in given merkle tree
    #[inline]
    pub fn verify(&self, root_hash: H256) -> bool
    where
        T: AsRef<[u8]>,
    {
        root_hash == self.root_hash && root_hash == self.path.node_hash && self.path.verify()
    }
}

/// Merkle tree with values of type `T`
#[derive(Debug)]
pub struct MerkleTree<T> {
    tree: Tree<T>,
    len: usize,
    height: usize,
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
                len,
                height,
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
        self.height
    }

    /// Returns the number of leaf nodes in merkle tree
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if current merkle tree is empty, `false` otherwise
    #[inline]
    pub fn is_empty(&self) -> bool {
        0 == self.len
    }

    /// Generates inclusion proof for given value. Returns `None` if given value is not present in merkle tree
    #[inline]
    pub fn generate_proof(&self, value: T) -> Option<Proof<T>>
    where
        T: AsRef<[u8]> + Clone,
    {
        let root_hash = self.root_hash();

        self.generate_path(value.clone()).map(|path| Proof {
            root_hash,
            path,
            value,
        })
    }

    /// Generates merkle path for given value. Returns `None` if given value is not present in merkle tree
    #[inline]
    fn generate_path(&self, value: T) -> Option<Path>
    where
        T: AsRef<[u8]> + Clone,
    {
        self.tree.generate_path(value)
    }
}

#[inline]
fn combine(left: &H256, right: &H256) -> H512 {
    let mut hash = [0; HASH_SIZE_256 * 2];
    hash[0..HASH_SIZE_256].copy_from_slice(left);
    hash[HASH_SIZE_256..(HASH_SIZE_256 * 2)].copy_from_slice(right);

    hash
}

#[inline]
fn hash<T: AsRef<[u8]>>(value: T) -> H256 {
    hash256::<Blake2s>(value.as_ref())
}

#[inline]
fn combined_hash(left: &H256, right: &H256) -> H256 {
    hash(&combine(left, right)[..])
}

/// An iterator which iterates over pair of values
pub struct PairIter<T> {
    inner: IntoIter<T>,
}

impl<T> From<IntoIter<T>> for PairIter<T> {
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

        assert_eq!(hash("one"), tree.root_hash());
        assert_eq!(0, tree.height());
        assert_eq!(1, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));
        assert!(tree.generate_proof("one").unwrap().verify(tree.root_hash()));
    }

    #[test]
    fn check_vec_2() {
        let values = vec!["one", "two"];
        let hashes = values.iter().map(hash).collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let root_hash = combined_hash(&hashes[0], &hashes[1]);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(1, tree.height());
        assert_eq!(2, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree.generate_proof("one").unwrap().verify(tree.root_hash()));
        assert!(tree.generate_proof("two").unwrap().verify(tree.root_hash()));
    }

    #[test]
    fn check_vec_3() {
        let values = vec!["one", "two", "three"];
        let hashes = values.iter().map(hash).collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = combined_hash(&hashes[0], &hashes[1]);
        let root_hash = combined_hash(&h01, &hashes[2]);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(2, tree.height());
        assert_eq!(3, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree.generate_proof("one").unwrap().verify(tree.root_hash()));
        assert!(tree.generate_proof("two").unwrap().verify(tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(tree.root_hash()));
    }

    #[test]
    fn check_vec_4() {
        let values = vec!["one", "two", "three", "four"];
        let hashes = values.iter().map(hash).collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = combined_hash(&hashes[0], &hashes[1]);
        let h23 = combined_hash(&hashes[2], &hashes[3]);

        let root_hash = combined_hash(&h01, &h23);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(2, tree.height());
        assert_eq!(4, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree.generate_proof("one").unwrap().verify(tree.root_hash()));
        assert!(tree.generate_proof("two").unwrap().verify(tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(tree.root_hash()));
    }

    #[test]
    fn check_vec_5() {
        let values = vec!["one", "two", "three", "four", "five"];
        let hashes = values.iter().map(hash).collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = combined_hash(&hashes[0], &hashes[1]);
        let h23 = combined_hash(&hashes[2], &hashes[3]);
        let h4 = combined_hash(&h01, &h23);

        let root_hash = combined_hash(&h4, &hashes[4]);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(3, tree.height());
        assert_eq!(5, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree.generate_proof("one").unwrap().verify(tree.root_hash()));
        assert!(tree.generate_proof("two").unwrap().verify(tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("five")
            .unwrap()
            .verify(tree.root_hash()));
    }

    #[test]
    fn check_vec_6() {
        let values = vec!["one", "two", "three", "four", "five", "six"];
        let hashes = values.iter().map(hash).collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = combined_hash(&hashes[0], &hashes[1]);
        let h23 = combined_hash(&hashes[2], &hashes[3]);
        let h45 = combined_hash(&hashes[4], &hashes[5]);

        let h6 = combined_hash(&h01, &h23);

        let root_hash = combined_hash(&h6, &h45);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(3, tree.height());
        assert_eq!(6, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree.generate_proof("one").unwrap().verify(tree.root_hash()));
        assert!(tree.generate_proof("two").unwrap().verify(tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("five")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree.generate_proof("six").unwrap().verify(tree.root_hash()));
    }

    #[test]
    fn check_vec_7() {
        let values = vec!["one", "two", "three", "four", "five", "six", "seven"];
        let hashes = values.iter().map(hash).collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = combined_hash(&hashes[0], &hashes[1]);
        let h23 = combined_hash(&hashes[2], &hashes[3]);
        let h45 = combined_hash(&hashes[4], &hashes[5]);

        let h6 = combined_hash(&h01, &h23);
        let h7 = combined_hash(&h45, &hashes[6]);

        let root_hash = combined_hash(&h6, &h7);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(3, tree.height());
        assert_eq!(7, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree.generate_proof("one").unwrap().verify(tree.root_hash()));
        assert!(tree.generate_proof("two").unwrap().verify(tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("five")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree.generate_proof("six").unwrap().verify(tree.root_hash()));
        assert!(tree
            .generate_proof("seven")
            .unwrap()
            .verify(tree.root_hash()));
    }

    #[test]
    fn check_vec_8() {
        let values = vec![
            "one", "two", "three", "four", "five", "six", "seven", "eight",
        ];
        let hashes = values.iter().map(hash).collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = combined_hash(&hashes[0], &hashes[1]);
        let h23 = combined_hash(&hashes[2], &hashes[3]);
        let h45 = combined_hash(&hashes[4], &hashes[5]);
        let h67 = combined_hash(&hashes[6], &hashes[7]);

        let h8 = combined_hash(&h01, &h23);
        let h9 = combined_hash(&h45, &h67);

        let root_hash = combined_hash(&h8, &h9);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(3, tree.height());
        assert_eq!(8, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree.generate_proof("one").unwrap().verify(tree.root_hash()));
        assert!(tree.generate_proof("two").unwrap().verify(tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("five")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree.generate_proof("six").unwrap().verify(tree.root_hash()));
        assert!(tree
            .generate_proof("seven")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("eight")
            .unwrap()
            .verify(tree.root_hash()));
    }

    #[test]
    fn check_vec_9() {
        let values = vec![
            "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
        ];
        let hashes = values.iter().map(hash).collect::<Vec<H256>>();

        let tree = MerkleTree::new(values);

        let h01 = combined_hash(&hashes[0], &hashes[1]);
        let h23 = combined_hash(&hashes[2], &hashes[3]);
        let h45 = combined_hash(&hashes[4], &hashes[5]);
        let h67 = combined_hash(&hashes[6], &hashes[7]);

        let h8 = combined_hash(&h01, &h23);
        let h9 = combined_hash(&h45, &h67);
        let h10 = combined_hash(&h8, &h9);

        let root_hash = combined_hash(&h10, &hashes[8]);

        assert_eq!(root_hash, tree.root_hash());
        assert_eq!(4, tree.height());
        assert_eq!(9, tree.len());
        assert_eq!(None, tree.generate_proof("ten"));

        assert!(tree.generate_proof("one").unwrap().verify(tree.root_hash()));
        assert!(tree.generate_proof("two").unwrap().verify(tree.root_hash()));
        assert!(tree
            .generate_proof("three")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("four")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("five")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree.generate_proof("six").unwrap().verify(tree.root_hash()));
        assert!(tree
            .generate_proof("seven")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("eight")
            .unwrap()
            .verify(tree.root_hash()));
        assert!(tree
            .generate_proof("nine")
            .unwrap()
            .verify(tree.root_hash()));
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
            .verify(new_tree.root_hash()));
    }
}
