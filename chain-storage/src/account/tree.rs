//! # Value with associated properties (e.g. min/max bounds)
//! adapted from https://github.com/ChosunOne/merkle_bit examples (Merkle-BIT)
//! Copyright (c) 2019, Josiah Evans (licensed under the MIT License and the Apache License, Version 2.0)
//! Modifications Copyright (c) 2019-2020, Foris Limited (licensed under the Apache License, Version 2.0)
//!

use blake2::{Blake2s, Digest};
use chain_core::common::H256;
use chain_core::state::account::Count;
use parity_scale_codec::{
    Decode as ScaleDecode, Encode as ScaleEncode, Error as ScaleError, Input, Output,
};
use starling::constants::KEY_LEN;
use starling::merkle_bit::{BinaryMerkleTreeResult, MerkleBIT};
use starling::traits::Hasher;
use starling::traits::{
    Branch, Data, Database, Decode, Encode, Exception, Leaf, Node, NodeVariant,
};
use starling::tree::tree_data::TreeData;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Blake2sHasher(Blake2s);
impl Hasher<H256> for Blake2sHasher {
    type HashType = Self;

    #[inline]
    fn new(_size: usize) -> Self {
        let hasher = Blake2s::new();
        Self(hasher)
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.0.input(data);
    }

    #[inline]
    fn finalize(self) -> [u8; KEY_LEN] {
        let result = self.0.result();
        let mut finalized = [0; KEY_LEN];
        finalized.copy_from_slice(result.as_ref());
        finalized
    }
}

pub type TreeHasher = Blake2sHasher;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TreeBranch {
    /// The number of leaf nodes under this branch.
    count: Count,
    /// The location of the next node when traversing the zero branch.
    zero: H256,
    /// The location of the next node when traversing the one branch.
    one: H256,
    /// The index bit of the associated key on which to make a decision to go down the zero or one branch.
    split_index: usize,
    /// The associated key with this branch.
    key: H256,
}

impl Branch<H256> for TreeBranch {
    #[inline]
    fn new() -> Self {
        let zero = [0u8; 32];
        TreeBranch {
            count: 0,
            zero,
            one: zero,
            split_index: 0,
            key: zero,
        }
    }

    #[inline]
    fn get_count(&self) -> u64 {
        self.count
    }
    #[inline]
    fn get_zero(&self) -> &[u8; KEY_LEN] {
        &self.zero
    }
    #[inline]
    fn get_one(&self) -> &[u8; KEY_LEN] {
        &self.one
    }
    #[inline]
    fn get_split_index(&self) -> usize {
        self.split_index
    }
    #[inline]
    fn get_key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    #[inline]
    fn set_count(&mut self, count: u64) {
        self.count = count
    }
    #[inline]
    fn set_zero(&mut self, zero: [u8; KEY_LEN]) {
        self.zero = zero
    }
    #[inline]
    fn set_one(&mut self, one: [u8; KEY_LEN]) {
        self.one = one
    }
    #[inline]
    fn set_split_index(&mut self, index: usize) {
        self.split_index = index
    }
    #[inline]
    fn set_key(&mut self, key: [u8; KEY_LEN]) {
        self.key = key
    }

    #[inline]
    fn decompose(self) -> (u64, [u8; KEY_LEN], [u8; KEY_LEN], usize, [u8; KEY_LEN]) {
        (
            self.get_count(),
            self.zero,
            self.one,
            self.get_split_index(),
            self.key,
        )
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TreeLeaf {
    /// The associated key with this node.
    key: H256,
    /// The location of the `Data` node in the tree.
    data: H256,
}

impl Leaf<H256> for TreeLeaf {
    /// Creates a new `TreeLeaf`
    #[inline]
    fn new() -> Self {
        let zero = [0u8; 32];
        TreeLeaf {
            key: zero,
            data: zero,
        }
    }

    /// Gets the associated key with this node.
    #[inline]
    fn get_key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    /// Gets the location of the `Data` node.
    #[inline]
    fn get_data(&self) -> &[u8; KEY_LEN] {
        &self.data
    }

    /// Sets the associated key with this node.
    #[inline]
    fn set_key(&mut self, key: [u8; KEY_LEN]) {
        self.key = key
    }

    /// Sets the location for the `Data` node.
    #[inline]
    fn set_data(&mut self, data: [u8; KEY_LEN]) {
        self.data = data
    }

    /// Decomposes the struct into its constituent parts.
    #[inline]
    fn decompose(self) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
        (self.key, self.data)
    }
}

/// A node in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeNode {
    /// The number of references to this node.
    pub references: Count,
    /// The `NodeVariant` of the node.
    pub node: NodeVariant<TreeBranch, TreeLeaf, TreeData, H256>,
}

impl ScaleEncode for TreeNode {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        match self.node {
            NodeVariant::Phantom(_) => {
                // TODO: panic or nothing?
            }
            NodeVariant::Branch(ref tb) => {
                // TreeBranch{count, zero, one, split_index, key}
                dest.push_byte(0);
                self.references.encode_to(dest);
                tb.count.encode_to(dest);
                tb.zero.encode_to(dest);
                tb.one.encode_to(dest);
                (tb.split_index as u64).encode_to(dest);
                tb.key.encode_to(dest);
            }
            NodeVariant::Leaf(ref tl) => {
                // TreeLeaf{key, data}
                dest.push_byte(1);
                self.references.encode_to(dest);
                tl.key.encode_to(dest);
                tl.data.encode_to(dest);
            }
            NodeVariant::Data(ref td) => {
                // TreeData{value}
                dest.push_byte(2);
                self.references.encode_to(dest);
                td.get_value().encode_to(dest);
            }
        }
    }
}

impl ScaleDecode for TreeNode {
    fn decode<I: Input>(input: &mut I) -> Result<Self, ScaleError> {
        let tag = input.read_byte()?;
        let references = u64::decode(input)?;
        match tag {
            0 => {
                let count = Count::decode(input)?;
                let zero = H256::decode(input)?;
                let one = H256::decode(input)?;
                let split_index: usize = u64::decode(input)? as usize;
                let key = H256::decode(input)?;
                Ok(TreeNode {
                    references,
                    node: NodeVariant::Branch(TreeBranch {
                        count,
                        zero,
                        one,
                        split_index,
                        key,
                    }),
                })
            }
            1 => {
                let key = H256::decode(input)?;
                let data = H256::decode(input)?;
                Ok(TreeNode {
                    references,
                    node: NodeVariant::Leaf(TreeLeaf { key, data }),
                })
            }
            2 => {
                let data: Vec<u8> = ScaleDecode::decode(input)?;
                let mut tree_data = TreeData::new();
                tree_data.set_value(&data);
                Ok(TreeNode {
                    references,
                    node: NodeVariant::Data(tree_data),
                })
            }
            _ => Err(ScaleError::from("Invalid tag")),
        }
    }
}

impl TreeNode {
    /// Creates a new `TreeNode`.
    #[inline]
    pub fn new(node_variant: NodeVariant<TreeBranch, TreeLeaf, TreeData, H256>) -> Self {
        Self {
            references: 0,
            node: node_variant,
        }
    }

    /// Gets the number of references to the node.
    fn get_references(&self) -> u64 {
        self.references
    }

    /// Sets the number of references to the node.
    fn set_references(&mut self, references: u64) {
        self.references = references;
    }

    /// Sets the node as a `NodeVariant::Branch`.
    fn set_branch(&mut self, branch: TreeBranch) {
        self.node = NodeVariant::Branch(branch);
    }

    /// Sets the node as a `NodeVariant::Leaf`.
    fn set_leaf(&mut self, leaf: TreeLeaf) {
        self.node = NodeVariant::Leaf(leaf);
    }

    /// Sets the node as a `NodeVariant::Data`.
    fn set_data(&mut self, data: TreeData) {
        self.node = NodeVariant::Data(data);
    }
}

impl Node<TreeBranch, TreeLeaf, TreeData, H256> for TreeNode {
    #[inline]
    fn new(node_variant: NodeVariant<TreeBranch, TreeLeaf, TreeData, H256>) -> Self {
        Self::new(node_variant)
    }
    #[inline]
    fn get_references(&self) -> u64 {
        Self::get_references(self)
    }
    #[inline]
    fn get_variant(self) -> NodeVariant<TreeBranch, TreeLeaf, TreeData, H256> {
        self.node
    }
    #[inline]
    fn set_references(&mut self, references: u64) {
        Self::set_references(self, references)
    }
    #[inline]
    fn set_branch(&mut self, branch: TreeBranch) {
        Self::set_branch(self, branch)
    }
    #[inline]
    fn set_leaf(&mut self, leaf: TreeLeaf) {
        Self::set_leaf(self, leaf)
    }
    #[inline]
    fn set_data(&mut self, data: TreeData) {
        Self::set_data(self, data)
    }
}

pub struct HashTree<ValueType, DatabaseType>
where
    ValueType: Encode + Decode + Sync + Send,
    DatabaseType: Database<H256, NodeType = TreeNode>,
{
    tree: MerkleBIT<
        DatabaseType,
        TreeBranch,
        TreeLeaf,
        TreeData,
        TreeNode,
        TreeHasher,
        ValueType,
        H256,
    >,
}

impl<ValueType, DatabaseType> HashTree<ValueType, DatabaseType>
where
    ValueType: Encode + Decode + Sync + Send,
    DatabaseType: Database<H256, NodeType = TreeNode>,
{
    /// Creates a new `HashTree`.
    #[inline]
    pub fn new(db: DatabaseType, depth: usize) -> BinaryMerkleTreeResult<Self> {
        let tree = MerkleBIT::from_db(db, depth)?;
        Ok(Self { tree })
    }

    /// Gets the values associated with `keys` from the tree.
    #[inline]
    pub fn get(
        &self,
        root_hash: &[u8; KEY_LEN],
        keys: &mut [[u8; KEY_LEN]],
    ) -> BinaryMerkleTreeResult<HashMap<[u8; KEY_LEN], Option<ValueType>>> {
        self.tree.get(root_hash, keys)
    }

    /// Gets one value associated with `key` from the tree.
    #[inline]
    pub fn get_one(
        &self,
        root_hash: &[u8; KEY_LEN],
        key: &[u8; KEY_LEN],
    ) -> BinaryMerkleTreeResult<Option<ValueType>> {
        self.tree.get_one(root_hash, key)
    }

    /// Inserts elements into the tree.  Using `previous_root` specifies that the insert depends on
    /// the state from the previous root, and will update references accordingly.
    #[inline]
    pub fn insert(
        &mut self,
        previous_root: Option<&[u8; KEY_LEN]>,
        keys: &mut [[u8; KEY_LEN]],
        values: &[ValueType],
    ) -> BinaryMerkleTreeResult<[u8; KEY_LEN]> {
        self.tree.insert(previous_root, keys, values)
    }

    /// Inserts one element into the tree.  Using `previous_root` specifies that the insert depends on
    /// the state from the previous root, and will update references accordingly.
    #[inline]
    pub fn insert_one(
        &mut self,
        previous_root: Option<&[u8; KEY_LEN]>,
        key: &[u8; KEY_LEN],
        value: &ValueType,
    ) -> BinaryMerkleTreeResult<[u8; KEY_LEN]> {
        self.tree.insert_one(previous_root, key, value)
    }

    /// Removes a root from the tree.  This will remove all elements with less than two references
    /// under the given root.
    #[inline]
    pub fn remove(&mut self, root_hash: &[u8; KEY_LEN]) -> BinaryMerkleTreeResult<()> {
        self.tree.remove(root_hash)
    }
}

#[inline]
pub fn convert_io_err(e: std::io::Error) -> Exception {
    Exception::new(&e.to_string())
}
