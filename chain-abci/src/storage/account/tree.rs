//! # Value with associated properties (e.g. min/max bounds)
//! adapted from https://github.com/ChosunOne/merkle_bit examples (Merkle-BIT)
//! Copyright (c) 2019, Josiah Evans (licensed under the MIT License and the Apache License, Version 2.0)
//! Modifications Copyright (c) 2019, Foris Limited (licensed under the Apache License, Version 2.0)
//!
//! TODO: WIP usage -- disallow dead_code when new TX types are added to work with accounts
#![allow(dead_code)]
use blake2::{Blake2s, Digest};
use chain_core::common::H256;
use chain_core::state::account::Count;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use starling::constants::KEY_LEN;
use starling::merkle_bit::{BinaryMerkleTreeResult, MerkleBIT};
use starling::traits::Hasher;
use starling::traits::{
    Branch, Data, Database, Decode, Encode, Exception, Leaf, Node, NodeVariant,
};
use starling::tree::tree_data::TreeData;
use std::collections::HashMap;
use std::error::Error;

#[derive(Clone)]
pub struct Blake2sHasher(Blake2s);
impl Hasher for Blake2sHasher {
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
    split_index: u8,
    /// The associated key with this branch.
    key: H256,
}

impl Branch for TreeBranch {
    #[inline]
    fn new() -> Self {
        let zero = [0u8; 32];
        TreeBranch {
            count: 0.into(),
            zero: zero.into(),
            one: zero.into(),
            split_index: 0,
            key: zero.into(),
        }
    }

    #[inline]
    fn get_count(&self) -> u64 {
        self.count.into()
    }
    #[inline]
    fn get_zero(&self) -> &[u8; KEY_LEN] {
        &self.zero.0
    }
    #[inline]
    fn get_one(&self) -> &[u8; KEY_LEN] {
        &self.one.0
    }
    #[inline]
    fn get_split_index(&self) -> u8 {
        self.split_index
    }
    #[inline]
    fn get_key(&self) -> &[u8; KEY_LEN] {
        &self.key.0
    }

    #[inline]
    fn set_count(&mut self, count: u64) {
        self.count = count.into()
    }
    #[inline]
    fn set_zero(&mut self, zero: [u8; KEY_LEN]) {
        self.zero = zero.into()
    }
    #[inline]
    fn set_one(&mut self, one: [u8; KEY_LEN]) {
        self.one = one.into()
    }
    #[inline]
    fn set_split_index(&mut self, index: u8) {
        self.split_index = index
    }
    #[inline]
    fn set_key(&mut self, key: [u8; KEY_LEN]) {
        self.key = key.into()
    }

    #[inline]
    fn deconstruct(self) -> (u64, [u8; KEY_LEN], [u8; KEY_LEN], u8, [u8; KEY_LEN]) {
        (
            self.get_count(),
            self.zero.0,
            self.one.0,
            self.get_split_index(),
            self.key.0,
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

impl Leaf for TreeLeaf {
    /// Creates a new `TreeLeaf`
    #[inline]
    fn new() -> Self {
        let zero = [0u8; 32];
        TreeLeaf {
            key: zero.into(),
            data: zero.into(),
        }
    }

    /// Gets the associated key with this node.
    #[inline]
    fn get_key(&self) -> &[u8; KEY_LEN] {
        &self.key.0
    }

    /// Gets the location of the `Data` node.
    #[inline]
    fn get_data(&self) -> &[u8; KEY_LEN] {
        &self.data.0
    }

    /// Sets the associated key with this node.
    #[inline]
    fn set_key(&mut self, key: [u8; KEY_LEN]) {
        self.key = key.into()
    }

    /// Sets the location for the `Data` node.
    #[inline]
    fn set_data(&mut self, data: [u8; KEY_LEN]) {
        self.data = data.into()
    }

    /// Decomposes the struct into its constituent parts.
    #[inline]
    fn deconstruct(self) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
        (self.key.0, self.data.0)
    }
}

/// A node in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeNode {
    /// The number of references to this node.
    pub references: Count,
    /// The `NodeVariant` of the node.
    pub node: NodeVariant<TreeBranch, TreeLeaf, TreeData>,
}

impl Encodable for TreeNode {
    fn rlp_append(&self, s: &mut RlpStream) {
        match &self.node {
            NodeVariant::Branch(tb) => {
                // TreeBranch{count, zero, one, split_index, key}
                s.begin_list(6)
                    .append(&self.references)
                    .append(&tb.count)
                    .append(&tb.zero)
                    .append(&tb.one)
                    .append(&tb.split_index)
                    .append(&tb.key);
            }
            NodeVariant::Leaf(tl) => {
                // TreeLeaf{key, data}
                s.begin_list(3)
                    .append(&self.references)
                    .append(&tl.key)
                    .append(&tl.data);
            }
            NodeVariant::Data(td) => {
                // TreeData{value}
                s.begin_list(2)
                    .append(&self.references)
                    .append(&td.get_value());
            }
        }
    }
}

impl Decodable for TreeNode {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let count = rlp.item_count()?;
        if count != 2 && count != 3 && count != 6 {
            return Err(DecoderError::Custom("Cannot decode a tree node"));
        }
        let references: Count = rlp.val_at(0)?;
        match count {
            2 => {
                let data: Vec<u8> = rlp.val_at(1)?;
                let mut tree_data = TreeData::new();
                tree_data.set_value(&data);
                Ok(TreeNode {
                    references,
                    node: NodeVariant::Data(tree_data),
                })
            }
            3 => {
                let key: H256 = rlp.val_at(1)?;
                let data: H256 = rlp.val_at(2)?;
                Ok(TreeNode {
                    references,
                    node: NodeVariant::Leaf(TreeLeaf { key, data }),
                })
            }
            6 => {
                let count: Count = rlp.val_at(1)?;
                let zero: H256 = rlp.val_at(2)?;
                let one: H256 = rlp.val_at(3)?;
                let split_index: u8 = rlp.val_at(4)?;
                let key: H256 = rlp.val_at(5)?;
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
            _ => unreachable!(),
        }
    }
}

impl TreeNode {
    /// Creates a new `TreeNode`.
    #[inline]
    pub fn new(node_variant: NodeVariant<TreeBranch, TreeLeaf, TreeData>) -> Self {
        Self {
            references: 0.into(),
            node: node_variant,
        }
    }

    /// Gets the number of references to the node.
    fn get_references(&self) -> u64 {
        self.references.into()
    }

    /// Sets the number of references to the node.
    fn set_references(&mut self, references: u64) {
        self.references = references.into();
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

impl Node<TreeBranch, TreeLeaf, TreeData> for TreeNode {
    #[inline]
    fn new(node_variant: NodeVariant<TreeBranch, TreeLeaf, TreeData>) -> Self {
        Self::new(node_variant)
    }
    #[inline]
    fn get_references(&self) -> u64 {
        Self::get_references(self)
    }
    #[inline]
    fn get_variant(self) -> NodeVariant<TreeBranch, TreeLeaf, TreeData> {
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
    DatabaseType: Database<NodeType = TreeNode>,
{
    tree: MerkleBIT<DatabaseType, TreeBranch, TreeLeaf, TreeData, TreeNode, TreeHasher, ValueType>,
}

impl<ValueType, DatabaseType> HashTree<ValueType, DatabaseType>
where
    ValueType: Encode + Decode + Sync + Send,
    DatabaseType: Database<NodeType = TreeNode>,
{
    /// Creates a new `HashTree`.
    #[inline]
    pub fn new(db: DatabaseType, depth: usize) -> BinaryMerkleTreeResult<Self> {
        let tree = MerkleBIT::from_db(db, depth)?;
        Ok(Self { tree })
    }

    /// Gets the values associated with `keys` from the tree.
    #[inline]
    pub fn get<'a>(
        &self,
        root_hash: &[u8; KEY_LEN],
        keys: &mut [&'a [u8; KEY_LEN]],
    ) -> BinaryMerkleTreeResult<HashMap<&'a [u8; KEY_LEN], Option<ValueType>>> {
        self.tree.get(root_hash, keys)
    }

    /// Inserts elements into the tree.  Using `previous_root` specifies that the insert depends on
    /// the state from the previous root, and will update references accordingly.
    #[inline]
    pub fn insert(
        &mut self,
        previous_root: Option<&[u8; KEY_LEN]>,
        keys: &mut [&[u8; KEY_LEN]],
        values: &mut [&ValueType],
    ) -> BinaryMerkleTreeResult<[u8; KEY_LEN]> {
        self.tree.insert(previous_root, keys, values)
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
    Exception::new(e.description())
}

#[inline]
pub fn convert_rlp_err(e: DecoderError) -> Exception {
    Exception::new(e.description())
}
