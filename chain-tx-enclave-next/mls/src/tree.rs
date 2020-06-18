use std::fmt;
use std::iter;

use crate::ciphersuite::CipherSuite;
use crate::extensions as ext;
use crate::group::ProcessCommitError;
use crate::key::{HPKEPrivateKey, HPKEPublicKey};
use crate::keypackage::{
    self as kp, KeyPackage, Timespec, MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
};
use crate::message::DirectPathNode;
use crate::message::*;
use crate::tree_math::{LeafSize, NodeSize};
use crate::utils::{decode_option, encode_option, encode_vec_u32, read_vec_u32};
use ra_client::AttestedCertVerifier;
use rustls::internal::msgs::codec::{self, Codec, Reader};
use secrecy::{ExposeSecret, SecretVec};
use subtle::ConstantTimeEq;

#[derive(Clone)]
/// spec: draft-ietf-mls-protocol.md#tree-hashes
pub struct ParentNode {
    pub public_key: HPKEPublicKey,
    // 0..2^32-1
    pub unmerged_leaves: Vec<u32>,
    // 0..255
    pub parent_hash: Vec<u8>,
    // optional private key, not participate in hash computation
    pub private_key: Option<HPKEPrivateKey>,
}

impl fmt::Debug for ParentNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParentNode")
            .field("public_key", &self.public_key)
            .field("unmerged_leaves", &self.unmerged_leaves)
            .field("parent_hash", &self.parent_hash)
            .finish()
    }
}

impl Codec for ParentNode {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public_key.encode(bytes);
        encode_vec_u32(bytes, &self.unmerged_leaves);
        codec::encode_vec_u8(bytes, &self.parent_hash);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let public_key = HPKEPublicKey::read(r)?;
        let unmerged_leaves = read_vec_u32(r)?;
        let parent_hash = codec::read_vec_u8(r)?;
        Some(Self {
            public_key,
            unmerged_leaves,
            parent_hash,
            private_key: None,
        })
    }
}

impl ParentNode {
    /// compute the parent hash to be referenced by children
    fn compute_parent_hash(&self, cs: CipherSuite) -> Vec<u8> {
        cs.hash(&self.get_encoding())
    }

    fn set_public_key(&mut self, public_key: HPKEPublicKey) {
        self.public_key = public_key;
        self.unmerged_leaves = vec![];
    }

    fn set_secret_verify_public(
        &mut self,
        cs: CipherSuite,
        secret: &SecretVec<u8>,
    ) -> Result<(), ()> {
        let private_key = cs.derive_private_key(secret);
        if !bool::from(
            private_key
                .public_key()
                .marshal()
                .ct_eq(&self.public_key.marshal()),
        ) {
            return Err(());
        }
        self.private_key = Some(private_key);
        Ok(())
    }
}

/// spec: draft-ietf-mls-protocol.md#tree-hashes
#[derive(Clone, Debug)]
pub enum Node {
    Leaf(Option<KeyPackage>),
    Parent(Option<ParentNode>),
}

impl Codec for Node {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Node::Leaf(kp) => {
                0u8.encode(bytes);
                encode_option(bytes, kp);
            }
            Node::Parent(pn) => {
                1u8.encode(bytes);
                encode_option(bytes, pn);
            }
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let tag = u8::read(r)?;
        match tag {
            0 => {
                let kp: Option<KeyPackage> = decode_option(r)?;
                Some(Node::Leaf(kp))
            }
            1 => {
                let np: Option<ParentNode> = decode_option(r)?;
                Some(Node::Parent(np))
            }
            _ => None,
        }
    }
}

impl Node {
    pub fn is_leaf(&self) -> bool {
        matches!(self, Node::Leaf(_))
    }

    pub fn is_empty_leaf(&self) -> bool {
        matches!(self, Node::Leaf(None))
    }

    pub fn is_empty_node(&self) -> bool {
        matches!(self, Node::Leaf(None) | Node::Parent(None))
    }

    pub fn parent_hash(&self) -> Option<Vec<u8>> {
        match self {
            Node::Leaf(Some(leaf)) => {
                Some(leaf.payload.find_extension::<ext::ParentHashExt>().ok()?.0)
            }
            Node::Parent(Some(parent)) => Some(parent.parent_hash.clone()),
            _ => None,
        }
    }

    /// Only blank node return None
    pub fn public_key(&self) -> Option<&HPKEPublicKey> {
        match self {
            Node::Leaf(Some(leaf)) => Some(&leaf.payload.init_key),
            Node::Parent(Some(parent)) => Some(&parent.public_key),
            _ => None,
        }
    }

    pub fn parent_node(&self) -> Option<&ParentNode> {
        match self {
            Node::Leaf(_) => panic!("invalid node type"),
            Node::Parent(ref pn) => pn.as_ref(),
        }
    }

    fn parent_node_mut(&mut self) -> Option<&mut ParentNode> {
        match self {
            Node::Leaf(_) => panic!("invalid node type"),
            Node::Parent(ref mut pn) => pn.as_mut(),
        }
    }

    /// compute the parent hash to be referenced by children
    ///
    /// blank node return empty vector.
    ///
    /// panic if called on leaf node.
    pub fn compute_parent_hash(&self, cs: CipherSuite) -> Vec<u8> {
        self.parent_node()
            .map(|pn| pn.compute_parent_hash(cs))
            .unwrap_or_default()
    }

    /// merge public key on parent node
    ///
    /// panic for leaf node
    fn merge_public(&mut self, public_key: HPKEPublicKey) {
        match self {
            Node::Leaf(_) => panic!("merge public on leaf node"),
            Node::Parent(None) => {
                *self = Node::Parent(Some(ParentNode {
                    public_key,
                    unmerged_leaves: vec![],
                    parent_hash: vec![],
                    private_key: None,
                }))
            }
            Node::Parent(Some(pn)) => pn.set_public_key(public_key),
        };
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
    pub my_pos: LeafSize,
}

impl Tree {
    pub fn get_package(&self, leaf_index: LeafSize) -> Option<&KeyPackage> {
        match self.nodes[NodeSize::from_leaf_index(leaf_index).0] {
            Node::Leaf(ref kp) => kp.as_ref(),
            _ => panic!("invalid node type"),
        }
    }

    /// Update keypackage of leaf node
    pub fn set_package(&mut self, leaf_index: LeafSize, kp: KeyPackage) {
        self.nodes[NodeSize::from_leaf_index(leaf_index).0] = Node::Leaf(Some(kp));
    }

    pub fn get_my_package(&self) -> &KeyPackage {
        self.get_package(self.my_pos).expect("corrupted tree")
    }

    /// Update keypackage of my leaf node
    pub fn set_my_package(&mut self, kp: KeyPackage) {
        self.set_package(self.my_pos, kp)
    }

    pub fn from_group_info(
        my_pos: LeafSize,
        cs: CipherSuite,
        nodes: Vec<Node>,
    ) -> Result<Self, kp::Error> {
        // FIXME: generate path secrets
        Ok(Self { nodes, cs, my_pos })
    }

    pub fn integrity_check(
        nodes: &[Node],
        ra_verifier: &impl AttestedCertVerifier,
        time: Timespec,
        cs: CipherSuite,
    ) -> Result<(), TreeIntegrityError> {
        let leaf_len = LeafSize::from_nodes(NodeSize(nodes.len()))
            .ok_or(TreeIntegrityError::CorruptedTree("node count is not even"))?;

        // leaf should be even position, and parent should be odd position
        for (i, node) in nodes.iter().enumerate() {
            if matches!(node, Node::Leaf(_)) && i % 2 != 0 {
                return Err(TreeIntegrityError::CorruptedTree("leaf index is not even"));
            }
            if matches!(node, Node::Parent(_)) && i % 2 != 1 {
                return Err(TreeIntegrityError::CorruptedTree("parent index is not odd"));
            }
        }

        for (i, node) in nodes.iter().enumerate() {
            match node {
                Node::Leaf(Some(kp)) => {
                    // "For each non-empty leaf node, verify the signature on the KeyPackage."
                    kp.verify(ra_verifier, time)?;
                }
                Node::Parent(Some(_)) => {
                    // "For each non-empty parent node, verify that exactly one of the node's children are non-empty
                    // and have the hash of this node set as their parent_hash value (if the child is another parent)
                    // or has a parent_hash extension in the KeyPackage containing the same value (if the child is a leaf)."
                    let x = NodeSize(i);
                    let left_pos = x.left().ok_or(TreeIntegrityError::CorruptedTree(
                        "parent node should have child",
                    ))?;
                    let right_pos = x.right(leaf_len).ok_or(TreeIntegrityError::CorruptedTree(
                        "parent node should have child",
                    ))?;
                    let parent_hash = match (
                        nodes[left_pos.0].parent_hash(),
                        nodes[right_pos.0].parent_hash(),
                    ) {
                        (None, Some(hash)) => hash,
                        (Some(hash), None) => hash,
                        _ => {
                            return Err(TreeIntegrityError::ParentHashEmpty);
                        }
                    };
                    if parent_hash
                        .ct_eq(&node_hash(&nodes, cs, x, leaf_len))
                        .into()
                    {
                        return Err(TreeIntegrityError::ParentHashDontMatch);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn for_group_info(&self) -> Vec<Option<Node>> {
        let mut result = Vec::with_capacity(self.nodes.len());
        for node in self.nodes.iter() {
            if node.is_empty_node() {
                result.push(None)
            } else {
                result.push(Some(node.clone()))
            }
        }
        result
    }

    fn get_free_leaf_or_extend(&mut self) -> NodeSize {
        match self.nodes.iter().position(|n| n.is_empty_leaf()) {
            Some(i) => NodeSize(i),
            None => {
                self.nodes.push(Node::Parent(None));
                self.nodes.push(Node::Leaf(None));
                NodeSize(self.nodes.len() - 1)
            }
        }
    }

    pub fn update(
        &mut self,
        add_proposals: &[MLSPlaintext],
        update_proposals: &[MLSPlaintext],
        remove_proposals: &[MLSPlaintext],
    ) -> Vec<(NodeSize, KeyPackage)> {
        for _update in update_proposals.iter() {
            // FIXME
        }
        for _remove in remove_proposals.iter() {
            // FIXME
        }
        let mut positions = Vec::with_capacity(add_proposals.len());
        for add in add_proposals.iter() {
            // position to add
            // "If necessary, extend the tree to the right until it has at least index + 1 leaves"
            let position = self.get_free_leaf_or_extend();
            let leafs = self.leaf_len();
            let dirpath = position.direct_path(leafs);
            for d in dirpath.iter() {
                let node = &mut self.nodes[d.0];
                if let Node::Parent(Some(ref mut np)) = node {
                    // "For each non-blank intermediate node along the
                    // path from the leaf at position index to the root,
                    // add index to the unmerged_leaves list for the node."
                    let du32 = d.0 as u32;
                    if !np.unmerged_leaves.contains(&du32) {
                        np.unmerged_leaves.push(du32);
                    }
                }
            }
            // "Set the leaf node in the tree at position index to a new node containing the public key
            // from the KeyPackage in the Add, as well as the credential under which the KeyPackage was signed"
            let leaf_node = Node::Leaf(add.get_add_keypackage());
            self.nodes[position.0] = leaf_node;
            positions.push((position, add.get_add_keypackage().expect("keypackage")));
        }
        positions
    }

    fn node_hash(&self, index: NodeSize) -> Vec<u8> {
        node_hash(&self.nodes, self.cs, index, self.leaf_len())
    }

    pub fn leaf_len(&self) -> LeafSize {
        LeafSize::from_nodes(NodeSize(self.nodes.len())).expect("invalid node count")
    }

    pub fn compute_tree_hash(&self) -> Vec<u8> {
        let root_index = NodeSize::root(self.leaf_len());
        self.node_hash(root_index)
    }

    pub fn init(creator_kp: KeyPackage) -> Self {
        let cs = if creator_kp.payload.cipher_suite == MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 {
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
        } else {
            panic!("unify the cipher suite representation")
        };
        Self {
            nodes: vec![Node::Leaf(Some(creator_kp))],
            // FIXME unify cipher_suite
            cs,
            my_pos: LeafSize(0),
        }
    }

    /// spec: draft-ietf-mls-protocol.md#ratchet-tree-evolution
    ///
    /// update path secrets
    ///
    /// returns: direct path nodes, parent_hash, commit_secret
    pub fn evolve(
        &mut self,
        ctx: &[u8],
        leaf_secret: SecretVec<u8>,
    ) -> (Vec<DirectPathNode>, Vec<u8>, SecretVec<u8>) {
        let leaf_len = self.leaf_len();
        let my_node = NodeSize::from_leaf_index(self.my_pos);
        let path = my_node.direct_path(leaf_len);
        let mut last_secret = leaf_secret;
        let mut path_nodes = vec![];

        // set path secrets up the tree and encrypt to the siblings.
        // the root node is the last node of path,
        // and n won't be the root node because of skip(1) in iterator.
        for (node, parent) in iter::once(my_node)
            .chain(path.iter().copied())
            .zip(path.iter().copied())
        {
            // path secret for parent
            last_secret = self
                .cs
                .expand_label(&last_secret, vec![], "path", &[], self.cs.secret_size())
                .expect("invalid length");

            // encrypt the secret to resolution maintained
            let sibling = node.sibling(leaf_len).expect("not root node");
            let encrypted_path_secret = resolve(&self.nodes, sibling)
                .iter()
                .map(|node| {
                    // encrypt to sibling's public key
                    let init_key = self.nodes[node.0].public_key().expect("not blank node");
                    self.cs
                        .encrypt(last_secret.expose_secret().clone(), &init_key, ctx)
                        .expect("encrypt failed")
                })
                .collect::<Vec<_>>();

            // derive keypair for parent
            let private_key = self.cs.derive_private_key(&last_secret);
            let public_key = private_key.public_key();

            path_nodes.push(DirectPathNode {
                public_key: public_key.clone(),
                encrypted_path_secret,
            });

            // update the parent node
            self.nodes[parent.0] = Node::Parent(Some(ParentNode {
                public_key,
                unmerged_leaves: vec![],
                parent_hash: vec![], // will set later
                private_key: Some(private_key),
            }));
        }

        // Define `commit_secret` as the value `path_secret[n+1]` derived from the
        // `path_secret[n]` value assigned to the root node.
        let commit_secret = self
            .cs
            .expand_label(&last_secret, vec![], "path", &[], self.cs.secret_size())
            .expect("invalid length");

        // update parent hash in path
        let leaf_parent_hash = self.set_parent_hash_path(self.my_pos);

        (path_nodes, leaf_parent_hash, commit_secret)
    }

    fn node_private_key<'a>(
        &'a self,
        node_index: NodeSize,
        leaf_private_key: &'a HPKEPrivateKey,
    ) -> Option<&'a HPKEPrivateKey> {
        let my_node = NodeSize::from_leaf_index(self.my_pos);
        if node_index == my_node {
            Some(leaf_private_key)
        } else {
            self.nodes[node_index.0]
                .parent_node()
                .and_then(|pn| pn.private_key.as_ref())
        }
    }

    /// find the intersection between sender and self.my_pos
    /// update the secrets along the path to root
    fn decrypt_path_secrets(
        &self,
        sender: LeafSize,
        ctx: &[u8],
        path_nodes: &[DirectPathNode],
        leaf_private_key: &HPKEPrivateKey,
    ) -> (NodeSize, SecretVec<u8>) {
        let leaf_len = self.leaf_len();
        if sender == self.my_pos {
            // same leaf
            let node_index = NodeSize::from_leaf_index(sender);
            (
                node_index.parent(leaf_len).expect("leaf node has parent"),
                self.cs
                    .expand_label(
                        &leaf_private_key.marshal(),
                        vec![],
                        "path",
                        &[],
                        self.cs.secret_size(),
                    )
                    .expect("invalid length"),
            )
        } else {
            let ancestor = NodeSize::ancestor_of(sender, self.my_pos);
            let my_node = if self.my_pos > sender {
                ancestor.right(leaf_len).expect("ancestor not leaf node")
            } else {
                ancestor.left().expect("ancestor not leaf node")
            };
            let path_node = NodeSize::from_leaf_index(sender)
                .direct_path(leaf_len)
                .into_iter()
                .zip(path_nodes.iter())
                .find(|(n, _)| *n == ancestor)
                .expect("invalid path nodes")
                .1;
            for (i, node_index) in resolve(&self.nodes, my_node).iter().copied().enumerate() {
                if let Some(private_key) = self.node_private_key(node_index, leaf_private_key) {
                    let secret = self
                        .cs
                        .decrypt(private_key, ctx, &path_node.encrypted_path_secret[i])
                        .expect("decrypt failed");
                    return (ancestor, SecretVec::new(secret));
                }
            }
            panic!("don't find private key to decrypt secret");
        }
    }

    /// draft-ietf-mls-protocol.md#synchronizing-views-of-the-tree
    ///
    /// find the overlap parent node, decrypt the secret and implant it
    ///
    /// returns (leaf_parent_hash, commit_secret)
    pub fn apply_path_secrets(
        &mut self,
        sender: LeafSize,
        ctx: &[u8],
        path_nodes: &[DirectPathNode],
        leaf_private_key: &HPKEPrivateKey,
    ) -> Result<(Vec<u8>, SecretVec<u8>), ProcessCommitError> {
        let leaf_len = self.leaf_len();
        let from = NodeSize::from_leaf_index(sender);
        // set public key
        for (node_index, path_node) in from
            .direct_path(leaf_len)
            .into_iter()
            .zip(path_nodes.iter())
        {
            self.nodes[node_index.0].merge_public(path_node.public_key.clone());
        }

        // Find overlap and decrypt the path secret
        let (overlap, mut last_secret) =
            self.decrypt_path_secrets(sender, ctx, path_nodes, leaf_private_key);

        // implant the path secret
        self.nodes[overlap.0]
            .parent_node_mut()
            .expect("implant invalid node")
            .set_secret_verify_public(self.cs, &last_secret)
            .map_err(|_| ProcessCommitError::PathSecretPublicKeyDontMatch)?;
        for node_index in overlap.direct_path(leaf_len).iter() {
            last_secret = self
                .cs
                .expand_label(&last_secret, vec![], "path", &[], self.cs.secret_size())
                .expect("invalid length");
            self.nodes[node_index.0]
                .parent_node_mut()
                .expect("implant invalid node")
                .set_secret_verify_public(self.cs, &last_secret)
                .map_err(|_| ProcessCommitError::PathSecretPublicKeyDontMatch)?;
        }

        // Define `commit_secret` as the value `path_secret[n+1]` derived from the
        // `path_secret[n]` value assigned to the root node.
        let commit_secret = self
            .cs
            .expand_label(&last_secret, vec![], "path", &[], self.cs.secret_size())
            .expect("invalid length");

        // update parent hash
        let leaf_parent_hash = self.set_parent_hash_path(sender);

        Ok((leaf_parent_hash, commit_secret))
    }

    fn set_parent_hash_path(&mut self, sender: LeafSize) -> Vec<u8> {
        let from = NodeSize::from_leaf_index(sender);
        let path = from.direct_path(self.leaf_len());
        for (node, parent) in path.iter().copied().zip(path.iter().skip(1).copied()).rev() {
            // no leaf node
            let hash = self.nodes[parent.0].compute_parent_hash(self.cs);
            if let Some(n) = self.nodes[node.0].parent_node_mut() {
                n.parent_hash = hash;
            }
        }
        self.nodes[path[0].0].compute_parent_hash(self.cs)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TreeIntegrityError {
    #[error("keypackage verify failed: {0}")]
    KeyPackageVerifyFail(#[from] kp::Error),
    #[error("corrupted tree structure: {0}")]
    CorruptedTree(&'static str),
    #[error("children don't have parent hash")]
    ParentHashEmpty,
    #[error("parent hash value don't match")]
    ParentHashDontMatch,
}

/// draft-ietf-mls-protocol.md#tree-hashes
fn node_hash(nodes: &[Node], cs: CipherSuite, index: NodeSize, leaf_size: LeafSize) -> Vec<u8> {
    let node = &nodes[index.0];
    let payload = match node {
        Node::Leaf(kp) => LeafNodeHashInput {
            node_index: index.0 as u32,
            key_package: kp.clone(),
        }
        .get_encoding(),
        Node::Parent(pn) => {
            let left_index = index.left().expect("parent node won't panic");
            let left_hash = node_hash(nodes, cs, left_index, leaf_size);
            let right_index = index.right(leaf_size).expect("parent node won't panic");
            let right_hash = node_hash(nodes, cs, right_index, leaf_size);
            ParentNodeHashInput {
                node_index: index.0 as u32,
                parent_node: pn.clone(),
                left_hash,
                right_hash,
            }
            .get_encoding()
        }
    };
    cs.hash(&payload)
}

/// draft-ietf-mls-protocol.md#ratchet-tree-nodes
/// no blank nodes return
fn resolve(nodes: &[Node], index: NodeSize) -> Vec<NodeSize> {
    match &nodes[index.0] {
        // Resolution of blank leaf is the empty list
        Node::Leaf(None) => vec![],
        // Resolution of non-blank leaf is node itself
        Node::Leaf(Some(_)) => vec![index],
        // Resolution of blank intermediate node is concatenation of the resolutions
        // of the children
        Node::Parent(None) => [
            resolve(nodes, index.left().expect("not leaf node")),
            resolve(
                nodes,
                index
                    .right(LeafSize::from_nodes(NodeSize(nodes.len())).expect("invalid node size"))
                    .expect("not leaf node"),
            ),
        ]
        .concat(),
        // Resolution of non-blank leaf is node + unmerged leaves
        Node::Parent(Some(p)) => iter::once(index)
            .chain(
                p.unmerged_leaves
                    .iter()
                    .map(|n| NodeSize::from_leaf_index(LeafSize(*n as usize))),
            )
            .collect::<Vec<_>>(),
    }
}
