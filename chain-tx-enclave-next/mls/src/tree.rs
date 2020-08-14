use std::convert::TryFrom;
use std::fmt;
use std::iter;

use chain_util::NonEmpty;
use ra_client::AttestedCertVerifier;
use secrecy::{ExposeSecret, Secret};
use subtle::ConstantTimeEq;

use crate::ciphersuite::{CipherSuite, HashValue, NodeSecret};
use crate::crypto::{decrypt_path_secret, encrypt_path_secret};
use crate::error::{CommitError, ProcessWelcomeError, TreeIntegrityError};
use crate::extensions as ext;
use crate::extensions::{ExtensionType, MLSExtension};
use crate::key::{derive_keypair, HPKEPrivateKey, HPKEPublicKey};
use crate::keypackage::{KeyPackage, Timespec};
use crate::message::{Add, DirectPathNode, ProposalId, Remove, Update};
use crate::tree_math::{LeafSize, NodeSize, NodeType, ParentSize};
use crate::utils;
use crate::utils::{decode_option, encode_option, encode_vec_u32, read_vec_u32};
use crate::{Codec, Reader};

#[derive(Clone)]
/// spec: draft-ietf-mls-protocol.md#tree-hashes
pub struct ParentNode<CS: CipherSuite> {
    pub public_key: HPKEPublicKey<CS>,
    // 0..2^32-1
    pub unmerged_leaves: Vec<u32>,
    // 0..255
    pub parent_hash: Option<HashValue<CS>>,
}

impl<CS: CipherSuite> fmt::Debug for ParentNode<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParentNode")
            .field("public_key", &self.public_key)
            .field("unmerged_leaves", &self.unmerged_leaves)
            .field("parent_hash", &self.parent_hash)
            .finish()
    }
}

impl<CS: CipherSuite> Codec for ParentNode<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public_key.encode(bytes);
        encode_vec_u32(bytes, &self.unmerged_leaves);
        utils::encode_vec_u8_u8(bytes, self.parent_hash.as_ref().map_or(&[], |h| h.as_ref()));
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let public_key = HPKEPublicKey::read(r)?;
        let unmerged_leaves = read_vec_u32(r)?;

        let v = utils::read_vec_u8_u8(r)?;
        let parent_hash = if v.is_empty() {
            None
        } else {
            Some(HashValue::try_from(v.as_slice()).ok()?)
        };

        Some(Self {
            public_key,
            unmerged_leaves,
            parent_hash,
        })
    }
}

impl<CS: CipherSuite> ParentNode<CS> {
    /// compute the parent hash to be referenced by children
    fn compute_parent_hash(&self) -> HashValue<CS> {
        CS::hash(&self.get_encoding())
    }

    fn set_public_key(&mut self, public_key: HPKEPublicKey<CS>) {
        self.public_key = public_key;
        self.unmerged_leaves = vec![];
    }
}

/// spec: draft-ietf-mls-protocol.md#tree-hashes
#[derive(Clone, Debug)]
pub enum Node<CS: CipherSuite> {
    Leaf(KeyPackage<CS>),
    Parent(ParentNode<CS>),
}

impl<CS: CipherSuite> Codec for Node<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Node::Leaf(kp) => {
                0u8.encode(bytes);
                kp.encode(bytes);
            }
            Node::Parent(pn) => {
                1u8.encode(bytes);
                pn.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let tag = u8::read(r)?;
        match tag {
            0 => Some(Node::Leaf(KeyPackage::read(r)?)),
            1 => Some(Node::Parent(ParentNode::read(r)?)),
            _ => None,
        }
    }
}

impl<CS: CipherSuite> Node<CS> {
    pub fn is_leaf(&self) -> bool {
        matches!(self, Node::Leaf(_))
    }

    pub fn parent_hash(&self) -> Option<HashValue<CS>> {
        match self {
            Node::Leaf(leaf) => {
                leaf.payload
                    .find_extension::<ext::ParentHashExt<CS>>()
                    .ok()?
                    .0
            }
            Node::Parent(parent) => parent.parent_hash.clone(),
        }
    }

    /// returns public key of parent node of leaf node
    pub fn public_key(&self) -> &HPKEPublicKey<CS> {
        match self {
            Node::Leaf(leaf) => &leaf.payload.init_key,
            Node::Parent(parent) => &parent.public_key,
        }
    }

    pub fn parent_node(&self) -> &ParentNode<CS> {
        match self {
            Node::Leaf(_) => panic!("invalid node type, checked in integrity_check"),
            Node::Parent(pn) => pn,
        }
    }

    fn parent_node_mut(&mut self) -> &mut ParentNode<CS> {
        match self {
            Node::Leaf(_) => panic!("invalid node type, checked in integrity_check"),
            Node::Parent(pn) => pn,
        }
    }

    /// merge public key on parent node
    ///
    /// panic for leaf node
    fn merge_public(&mut self, public_key: HPKEPublicKey<CS>) {
        match self {
            Node::Leaf(_) => panic!("merge public on leaf node"),

            Node::Parent(pn) => pn.set_public_key(public_key),
        };
    }
}

/// spec: draft-ietf-mls-protocol.md#parent-hash
#[derive(Debug)]
pub struct RatchetTreeExt<CS: CipherSuite> {
    pub nodes: Vec<Option<Node<CS>>>,
}

impl<CS: CipherSuite> Codec for RatchetTreeExt<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        utils::encode_vec_option_u32(bytes, &self.nodes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        utils::read_vec_option_u32(r).map(|nodes| Self { nodes })
    }
}

impl<CS: CipherSuite> MLSExtension for RatchetTreeExt<CS> {
    const EXTENSION_TYPE: ExtensionType = ExtensionType::RatchetTree;
}

impl<CS: CipherSuite> RatchetTreeExt<CS> {
    pub fn new(nodes: Vec<Option<Node<CS>>>) -> Self {
        Self { nodes }
    }
}

#[derive(Debug)]
/// spec: draft-ietf-mls-protocol.md#tree-hashes
pub struct ParentNodeHashInput<CS: CipherSuite> {
    pub node_index: NodeSize,
    pub parent_node: Option<ParentNode<CS>>,
    pub left_hash: HashValue<CS>,
    pub right_hash: HashValue<CS>,
}

impl<CS: CipherSuite> Codec for ParentNodeHashInput<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.node_index.0.encode(bytes);
        encode_option(bytes, &self.parent_node);
        self.left_hash.encode(bytes);
        self.right_hash.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let node_index = NodeSize(u32::read(r)?);
        let parent_node: Option<ParentNode<CS>> = decode_option(r)?;
        let left_hash = HashValue::read(r)?;
        let right_hash = HashValue::read(r)?;

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
pub struct LeafNodeHashInput<CS: CipherSuite> {
    /// Note that the `node_index` field contains the index of the leaf among the nodes
    /// in the tree, not its index among the leaves; `node_index = 2 * leaf_index`.
    pub node_index: NodeSize,
    pub key_package: Option<KeyPackage<CS>>,
}

impl<CS: CipherSuite> Codec for LeafNodeHashInput<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.node_index.0.encode(bytes);
        encode_option(bytes, &self.key_package);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let node_index = NodeSize(u32::read(r)?);
        let key_package: Option<KeyPackage<CS>> = decode_option(r)?;

        Some(Self {
            node_index,
            key_package,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#ratchet-tree-extension
/// TODO: https://github.com/mlswg/mls-protocol/pull/327/files
///
/// Invariants:
/// - there's at least one leaf node
#[derive(Clone)]
pub struct TreePublicKey<CS: CipherSuite> {
    /// all tree nodes stored in a vector
    pub nodes: Vec<Option<Node<CS>>>,
}

impl<CS: CipherSuite> TreePublicKey<CS> {
    /// construct single leaf tree
    pub fn new(kp: KeyPackage<CS>) -> Self {
        TreePublicKey {
            nodes: vec![Some(Node::Leaf(kp))],
        }
    }

    /// construct from group info object in welcome message
    pub fn from_group_info(
        nodes: Vec<Option<Node<CS>>>,
        ra_verifier: &impl AttestedCertVerifier,
        time: Timespec,
    ) -> Result<Self, TreeIntegrityError> {
        Self::integrity_check(&nodes, ra_verifier, time)?;
        Ok(Self { nodes })
    }

    pub fn get(&self, index: NodeSize) -> Option<&Node<CS>> {
        self.nodes
            .get(index.0 as usize)
            .and_then(|opt| opt.as_ref())
    }

    pub fn get_package(&self, leaf_index: LeafSize) -> Option<&KeyPackage<CS>> {
        self.get(leaf_index.into()).map(|node| match node {
            Node::Leaf(kp) => kp,
            _ => unreachable!("corrupted tree, checked in integrity_check"),
        })
    }

    pub fn get_package_mut(&mut self, leaf_index: LeafSize) -> Option<&mut KeyPackage<CS>> {
        self.nodes[leaf_index.node_index()]
            .as_mut()
            .map(|node| match node {
                Node::Leaf(kp) => kp,
                _ => unreachable!("corrupted tree, checked in integrity_check"),
            })
    }

    /// Update keypackage of leaf node
    ///
    /// Panic if `leaf_index` is out of range
    pub fn set_package(&mut self, leaf_index: LeafSize, kp: KeyPackage<CS>) {
        self.nodes[leaf_index.node_index()] = Some(Node::Leaf(kp));
    }

    pub fn get_parent_node(&self, pos: ParentSize) -> Option<&ParentNode<CS>> {
        self.get(pos.into()).map(|node| match node {
            Node::Leaf(_) => unreachable!("invalid node type, checked in integrity_check"),
            Node::Parent(pn) => pn,
        })
    }

    /// Check TreeIntegrityError's branches for invariants list
    fn integrity_check(
        nodes: &[Option<Node<CS>>],
        ra_verifier: &impl AttestedCertVerifier,
        time: Timespec,
    ) -> Result<(), TreeIntegrityError> {
        if nodes.is_empty() {
            return Err(TreeIntegrityError::EmptyTree);
        }
        let nodes_len =
            u32::try_from(nodes.len()).map_err(|_| TreeIntegrityError::NodeCountOverflow)?;
        let leafs_len = NodeSize(nodes_len)
            .leafs_len()
            .ok_or(TreeIntegrityError::NodeCountNotEven)?;

        // leaf should be even position, and parent should be odd position
        for (i, node) in nodes.iter().enumerate() {
            if matches!(node, Some(Node::Leaf(_))) && i % 2 != 0 {
                return Err(TreeIntegrityError::LeafIndexIsNotEven);
            }
            if matches!(node, Some(Node::Parent(_))) && i % 2 != 1 {
                return Err(TreeIntegrityError::ParentIndexIsNotOdd);
            }
        }

        for (i, node) in nodes.iter().enumerate() {
            match node {
                Some(Node::Leaf(kp)) => {
                    // "For each non-empty leaf node, verify the signature on the KeyPackage."
                    kp.verify(ra_verifier, time)?;
                }
                Some(Node::Parent(pn)) => {
                    // "For each non-empty parent node, verify that exactly one of the node's children are non-empty
                    // and have the hash of this node set as their parent_hash value (if the child is another parent)
                    // or has a parent_hash extension in the KeyPackage containing the same value (if the child is a leaf)."
                    let x = NodeSize(i as u32);
                    let px = ParentSize::try_from(x).map_err(|_| {
                        TreeIntegrityError::CorruptedTree("should be parent node index")
                    })?;
                    let left_pos = px.left();
                    let right_pos = px.right(leafs_len);
                    let computed_parent_hash = pn.compute_parent_hash();
                    let parent_hash = match (
                        nodes[left_pos.node_index()]
                            .as_ref()
                            .and_then(|node| node.parent_hash()),
                        nodes[right_pos.node_index()]
                            .as_ref()
                            .and_then(|node| node.parent_hash()),
                    ) {
                        (None, Some(hash)) => hash,
                        (Some(hash), None) => hash,
                        _ => {
                            return Err(TreeIntegrityError::ParentHashEmpty);
                        }
                    };
                    if !bool::from(parent_hash.ct_eq(&computed_parent_hash)) {
                        return Err(TreeIntegrityError::ParentHashDontMatch);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // failed if node size overflowed u32
    fn get_free_leaf_or_extend(&mut self) -> Result<LeafSize, <u32 as TryFrom<usize>>::Error> {
        // nodes length overflow is verified in integrity_check
        let found_leaf_index = self
            .iter_nodes()
            .filter_map(|(node_type, node)| match (node_type, node) {
                // find a empty leaf node
                (NodeType::Leaf(index), None) => Some(index),
                _ => None,
            })
            .next();
        match found_leaf_index {
            Some(i) => Ok(i),
            None => {
                // check the last leaf node index
                let index = NodeSize(u32::try_from(self.nodes.len() + 2 - 1)?);
                self.nodes.push(None); // parent
                self.nodes.push(None); // leaf
                Ok(LeafSize::try_from(index)
                    .expect("node count is odd, checked in integrity_check"))
            }
        }
    }

    /// Return newly added positions and keypackages
    pub fn update(
        &mut self,
        adds: &[Add<CS>],
        updates: &[(LeafSize, Update<CS>, ProposalId<CS>)],
        removes: &[Remove],
    ) -> Result<Vec<(LeafSize, KeyPackage<CS>)>, CommitError> {
        // spec: draft-ietf-mls-protocol.md#update
        for (sender, update, _) in updates.iter() {
            self.set_package(*sender, update.key_package.clone());
            for p in NodeSize::from(*sender).direct_path(self.leaf_len()) {
                self.nodes[p.node_index()] = None;
            }
        }
        // spec: draft-ietf-mls-protocol.md#remove
        for remove in removes.iter() {
            let removed = NodeSize::from(remove.removed);
            self.nodes[removed.node_index()] = None;
            for p in removed.direct_path(self.leaf_len()) {
                self.nodes[p.node_index()] = None;
            }
        }
        let mut positions = Vec::with_capacity(adds.len());
        for add in adds.iter() {
            // position to add
            // "If necessary, extend the tree to the right until it has at least index + 1 leaves"
            let position = self
                .get_free_leaf_or_extend()
                .map_err(|_| CommitError::TooManyNodes)?;
            let dirpath = NodeSize::from(position).direct_path(self.leaf_len());
            for d in dirpath.iter() {
                let node = &mut self.nodes[d.node_index()];
                if let Some(Node::Parent(np)) = node {
                    // "For each non-blank intermediate node along the
                    // path from the leaf at position index to the root,
                    // add index to the unmerged_leaves list for the node."
                    if !np.unmerged_leaves.contains(&d.0) {
                        np.unmerged_leaves.push(d.0);
                    }
                }
            }
            // "Set the leaf node in the tree at position index to a new node containing the public key
            // from the KeyPackage in the Add, as well as the credential under which the KeyPackage was signed"
            self.set_package(position, add.key_package.clone());
            positions.push((position, add.key_package.clone()));
        }
        Ok(positions)
    }

    fn node_hash(&self, index: NodeSize) -> HashValue<CS> {
        node_hash(&self.nodes, index, self.leaf_len())
    }

    pub fn leaf_len(&self) -> LeafSize {
        // node count is verified in integrity_check
        u32::try_from(self.nodes.len())
            .ok()
            .and_then(|len| NodeSize(len).leafs_len())
            .expect("impossible, invalid node length, checked in integrity_check")
    }

    pub fn compute_tree_hash(&self) -> HashValue<CS> {
        let root_index = NodeSize::root(self.leaf_len());
        self.node_hash(root_index)
    }

    /// creator_kp should be verified already
    pub fn init(creator_kp: KeyPackage<CS>) -> Self {
        Self {
            nodes: vec![Some(Node::Leaf(creator_kp))],
        }
    }

    /// spec: draft-ietf-mls-protocol.md#ratchet-tree-evolution
    ///
    /// update path secrets
    ///
    /// returns: direct path nodes, parent_hash, tree_secret
    pub fn evolve(
        &mut self,
        ctx: &[u8],
        my_pos: LeafSize,
        leaf_secret: &Secret<NodeSecret<CS>>,
    ) -> Result<
        (
            Vec<DirectPathNode<CS>>,
            Option<HashValue<CS>>,
            TreeSecret<CS>,
        ),
        CommitError,
    > {
        let tree_secret = TreeSecret::new(my_pos.into(), self.leaf_len(), &leaf_secret)?;
        let leaf_len = self.leaf_len();
        let my_node = NodeSize::from(my_pos);
        let path = my_node.direct_path(leaf_len);
        let mut path_nodes = vec![];

        // set path secrets up the tree and encrypt to the siblings.
        // the root node is the last node of path,
        // and n won't be the root node because of skip(1) in iterator.
        let full_path = iter::once(my_node).chain(path.iter().copied().map(NodeSize::from));
        let path_with_secrets = path.iter().copied().zip(tree_secret.path_secrets.iter());
        for (node, (parent, secret)) in full_path.zip(path_with_secrets) {
            // encrypt the secret to resolution maintained
            let sibling = node
                .sibling(leaf_len)
                .expect("impossible, node is not root node");
            let encrypted_path_secret = self
                .resolve(sibling)
                .iter()
                .map(|node| {
                    // encrypt to sibling's public key
                    let init_key = self.nodes[node.node_index()]
                        .as_ref()
                        .expect("not blank node TODO")
                        .public_key();
                    encrypt_path_secret(&secret, &init_key, ctx)
                })
                .collect::<Result<Vec<_>, _>>()?;

            // derive keypair for parent
            let (_, public_key) = derive_keypair(secret.expose_secret().as_ref());

            path_nodes.push(DirectPathNode {
                public_key: public_key.clone(),
                encrypted_path_secret,
            });

            // update the parent node
            self.nodes[parent.node_index()] = Some(Node::Parent(ParentNode {
                public_key,
                unmerged_leaves: vec![],
                parent_hash: None, // will set later
            }));
        }

        // update parent hash in path
        let leaf_parent_hash = self.set_parent_hash_path(my_pos);

        Ok((path_nodes, leaf_parent_hash, tree_secret))
    }

    /// merge parent node public keys from `DirectPath`
    pub fn merge(
        &mut self,
        sender: LeafSize,
        path_nodes: &[DirectPathNode<CS>],
    ) -> Option<HashValue<CS>> {
        let leaf_len = self.leaf_len();
        let from = NodeSize::from(sender);
        // set public key
        for (node_index, path_node) in from
            .direct_path(leaf_len)
            .into_iter()
            .zip(path_nodes.iter())
        {
            match &mut self.nodes[node_index.node_index()] {
                None => {
                    self.nodes[node_index.node_index()] = Some(Node::Parent(ParentNode {
                        public_key: path_node.public_key.clone(),
                        unmerged_leaves: vec![],
                        parent_hash: None,
                    }));
                }
                Some(p) => {
                    p.merge_public(path_node.public_key.clone());
                }
            }
        }

        // update parent hash
        self.set_parent_hash_path(sender)
    }

    fn set_parent_hash_path(&mut self, sender: LeafSize) -> Option<HashValue<CS>> {
        let from = NodeSize::from(sender);
        let path = from.direct_path(self.leaf_len());
        for (node, parent) in path.iter().copied().zip(path.iter().skip(1).copied()).rev() {
            // no leaf node
            let hash = self.compute_parent_hash(parent);
            if let Some(node) = &mut self.nodes[node.node_index()] {
                node.parent_node_mut().parent_hash = hash;
            }
        }
        path.first().and_then(|&p| self.compute_parent_hash(p))
    }

    /// compute the parent hash to be referenced by children
    ///
    /// blank node return empty vector.
    ///
    /// panic if called on leaf node.
    fn compute_parent_hash(&self, index: ParentSize) -> Option<HashValue<CS>> {
        self.get_parent_node(index)
            .map(|node| node.compute_parent_hash())
    }

    /// Verify the secret match the public key in the parent node
    pub(crate) fn verify_node_private_key(
        &self,
        secret: &Secret<NodeSecret<CS>>,
        pos: ParentSize,
    ) -> Result<(), ()> {
        if let Some(node) = self.get_parent_node(pos) {
            let (_, public_key) = derive_keypair::<CS>(secret.expose_secret().as_ref());
            if bool::from(public_key.marshal().ct_eq(&node.public_key.marshal())) {
                return Ok(());
            }
        }
        Err(())
    }

    /// draft-ietf-mls-protocol.md#ratchet-tree-nodes
    /// no blank nodes return
    pub(crate) fn resolve(&self, index: NodeSize) -> Vec<NodeSize> {
        match (index.node_type(), &self.nodes[index.node_index()]) {
            // Resolution of blank leaf is the empty list
            (NodeType::Leaf(_), None) => vec![],
            // Resolution of non-blank leaf is node itself
            (NodeType::Leaf(_), Some(Node::Leaf(_))) => vec![index],
            // Resolution of blank intermediate node is concatenation of the resolutions
            // of the children
            (NodeType::Parent(pindex), None) => [
                self.resolve(pindex.left()),
                self.resolve(pindex.right(self.leaf_len())),
            ]
            .concat(),
            // Resolution of non-blank leaf is node + unmerged leaves
            (NodeType::Parent(_), Some(Node::Parent(p))) => iter::once(index)
                .chain(
                    p.unmerged_leaves
                        .iter()
                        .copied()
                        .map(|n| NodeSize::from(LeafSize(n))),
                )
                .collect::<Vec<_>>(),
            _ => unreachable!("corrupted tree, checked in integrity_check"),
        }
    }

    /// iterate nodes with node type and index
    pub fn iter_nodes(&self) -> impl Iterator<Item = (NodeType, Option<&Node<CS>>)> {
        self.nodes.iter().enumerate().map(|(i, node)| {
            (
                NodeSize(u32::try_from(i).expect("checked in integrity_check")).node_type(),
                node.as_ref(),
            )
        })
    }
}

/// Store the path secrets for a leaf node.
///
/// For example, in this tree:
///
/// ```plain
///                                              X
///                      X
///          X                       X                       X
///    X           X           X           X           X
/// X     X     X     X     X     X     X     X     X     X     X
/// 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20
/// ```
///
/// The direct path of leaf 0 is [1, 3, 7, 15], the secret of the nodes in the direct path is
/// stored in `path_secrets`, and the secrets for the leaf node itself is stored in `kp_secret` in
/// `GroupAux`.
///
/// The `update_secret` is derived from the secret of the root node.
pub struct TreeSecret<CS: CipherSuite> {
    /// Not including leaf private key
    pub path_secrets: Vec<Secret<NodeSecret<CS>>>,
    /// The commit secret
    pub update_secret: Secret<NodeSecret<CS>>,
}

impl<CS: CipherSuite> Default for TreeSecret<CS> {
    fn default() -> Self {
        Self {
            path_secrets: vec![],
            update_secret: Secret::new(Default::default()),
        }
    }
}

impl<CS: CipherSuite> TreeSecret<CS> {
    pub fn new(
        start: NodeSize,
        leaf_len: LeafSize,
        secret: &Secret<NodeSecret<CS>>,
    ) -> Result<Self, hkdf::InvalidLength> {
        let mut path_secrets = vec![];
        for _ in start.direct_path(leaf_len).iter() {
            // path secret for parent
            path_secrets.push(CS::derive_path_secret(
                path_secrets.last().unwrap_or(secret).expose_secret(),
            ));
        }

        let update_secret =
            CS::derive_path_secret(&path_secrets.last().unwrap_or(secret).expose_secret());

        Ok(Self {
            path_secrets,
            update_secret,
        })
    }

    /// find the intersection between sender and my_pos,
    /// and decrypt the path secret.
    ///
    /// return the common ancestor node and decryted secret
    /// return None if tree only have one leaf
    fn decrypt_path_secrets(
        &self,
        sender: LeafSize,
        my_pos: LeafSize,
        tree: &TreePublicKey<CS>,
        ctx: &[u8],
        path_nodes: &[DirectPathNode<CS>],
        leaf_private_key: &HPKEPrivateKey<CS>,
    ) -> Result<Option<(ParentSize, Secret<NodeSecret<CS>>)>, CommitError> {
        let leaf_len = tree.leaf_len();
        let ancestor = ParentSize::common_ancestor(sender, my_pos);
        match ancestor {
            None => {
                // `sender` and `my_pos` are the same leaf node
                let node_index = NodeSize::from(sender);
                match node_index.parent(leaf_len) {
                    Some(node) => Ok(Some((
                        node,
                        CS::derive_path_secret(leaf_private_key.marshal().expose_secret()),
                    ))),
                    None => Ok(None),
                }
            }
            Some(ancestor) => {
                // find the path node correspounding to the ancestor
                let path_node = NodeSize::from(sender)
                    .direct_path(leaf_len)
                    .into_iter()
                    .zip(path_nodes.iter())
                    .find(|(n, _)| *n == ancestor)
                    .expect("impossible, ancestor must in direct_path of sender")
                    .1;
                // find the index of ancestor in the direct_path/path_secrets
                let pos = NodeSize::from(my_pos)
                    .direct_path(leaf_len)
                    .iter()
                    .position(|&p| p == ancestor)
                    .expect("impossible, ancestor must in direct path of my_pos");
                // move one level down from ancestor to get to the node the secret encrypted to,
                // `None` means it's leaf node under the ancestor.
                let secret = match pos.checked_sub(1) {
                    None => decrypt_path_secret(
                        &leaf_private_key,
                        ctx,
                        &path_node.encrypted_path_secret[0],
                    )?,
                    Some(pos) => decrypt_path_secret(
                        &HPKEPrivateKey::unmarshal(
                            self.path_secrets[pos].expose_secret().as_ref(),
                        )?,
                        ctx,
                        &path_node.encrypted_path_secret[0],
                    )?,
                };
                Ok(Some((ancestor, secret)))
            }
        }
    }

    /// draft-ietf-mls-protocol.md#synchronizing-views-of-the-tree
    ///
    /// find the overlap parent node, decrypt the secret and implant it
    ///
    /// it don't mutate self directly, but return a `TreeSecretDiff` which can be applied to
    /// `TreeSecret` later.
    pub(crate) fn apply_path_secrets(
        &self,
        sender: LeafSize,
        my_pos: LeafSize,
        tree: &TreePublicKey<CS>,
        ctx: &[u8],
        path_nodes: &[DirectPathNode<CS>],
        leaf_private_key: &HPKEPrivateKey<CS>,
    ) -> Result<TreeSecretDiff<CS>, CommitError> {
        let leaf_len = tree.leaf_len();
        // Find overlap and decrypt the path secret
        if let Some((overlap, overlap_secret)) =
            self.decrypt_path_secrets(sender, my_pos, tree, ctx, path_nodes, leaf_private_key)?
        {
            let diff = self.apply_overlap_secret(my_pos, tree, overlap, overlap_secret)?;

            // verify the new path secrets match public keys
            let overlap_path = NodeSize::from(overlap).direct_path(leaf_len);
            for (secret, &parent) in diff
                .path_secrets
                .iter()
                .zip(iter::once(&overlap).chain(overlap_path.iter()))
            {
                tree.verify_node_private_key(secret, parent)
                    .map_err(|_| CommitError::PathSecretPublicKeyDontMatch)?;
            }

            Ok(diff)
        } else {
            let update_secret = CS::derive_path_secret(leaf_private_key.marshal().expose_secret());
            Ok(TreeSecretDiff {
                overlap_pos: None,
                path_secrets: vec![],
                update_secret,
            })
        }
    }

    pub(crate) fn apply_welcome_secret(
        &mut self,
        sender: LeafSize,
        my_pos: LeafSize,
        secret: Secret<NodeSecret<CS>>,
        tree: &TreePublicKey<CS>,
    ) -> Result<(), ProcessWelcomeError> {
        let leaf_len = tree.leaf_len();
        let overlap =
            ParentSize::common_ancestor(sender, my_pos).ok_or(ProcessWelcomeError::SelfWelcome)?;
        let diff = self.apply_overlap_secret(my_pos, tree, overlap, secret)?;

        // verify the new path secrets match public keys
        let overlap_path = NodeSize::from(overlap).direct_path(leaf_len);
        for (secret, &parent) in diff
            .path_secrets
            .iter()
            .zip(iter::once(&overlap).chain(overlap_path.iter()))
        {
            tree.verify_node_private_key(secret, parent)
                .map_err(|_| ProcessWelcomeError::PathSecretPublicKeyDontMatch)?;
        }

        self.apply_tree_diff(diff);
        Ok(())
    }

    /// returns `(overlap_pos, path_secrets, update_secret)`
    fn apply_overlap_secret(
        &self,
        my_pos: LeafSize,
        tree: &TreePublicKey<CS>,
        overlap: ParentSize,
        overlap_secret: Secret<NodeSecret<CS>>,
    ) -> Result<TreeSecretDiff<CS>, hkdf::InvalidLength> {
        let leaf_len = tree.leaf_len();
        let direct_path = NodeSize::from(my_pos).direct_path(leaf_len);
        let overlap_pos = direct_path
            .iter()
            .position(|&p| p == overlap)
            .expect("impossible, overlap must in the direct path of my_pos");
        let overlap_path = &direct_path[overlap_pos + 1..];
        debug_assert_eq!(
            overlap_path.iter().copied().collect::<Vec<_>>(),
            NodeSize::from(overlap).direct_path(leaf_len)
        );

        // the path secrets above(including) the overlap node
        let mut path_secrets = NonEmpty::from(overlap_secret);
        for _ in overlap_path.iter() {
            path_secrets.push(CS::derive_path_secret(path_secrets.last().expose_secret()));
        }
        assert_eq!(overlap_pos + path_secrets.len().get(), direct_path.len());

        // Define `commit_secret` as the value `path_secret[n+1]` derived from the
        // `path_secret[n]` value assigned to the root node.
        let update_secret = CS::derive_path_secret(path_secrets.last().expose_secret());

        Ok(TreeSecretDiff {
            overlap_pos: Some(overlap_pos),
            path_secrets: path_secrets.into(),
            update_secret,
        })
    }

    pub(crate) fn apply_tree_diff(&mut self, tree_diff: TreeSecretDiff<CS>) {
        if let Some(overlap_pos) = tree_diff.overlap_pos {
            self.path_secrets.truncate(overlap_pos);
            self.path_secrets.extend(tree_diff.path_secrets);
        }
        self.update_secret = tree_diff.update_secret;
    }
}

/// Represent the diff needs to be applied later to `TreeSecret`
pub struct TreeSecretDiff<CS: CipherSuite> {
    /// the nodes from overlap_pos to root need to be updated
    ///
    /// None means no common ancestor
    pub overlap_pos: Option<usize>,
    /// the path secrets from(including) overlap_pos to root
    pub path_secrets: Vec<Secret<NodeSecret<CS>>>,
    pub update_secret: Secret<NodeSecret<CS>>,
}

/// draft-ietf-mls-protocol.md#tree-hashes
fn node_hash<CS: CipherSuite>(
    nodes: &[Option<Node<CS>>],
    index: NodeSize,
    leaf_size: LeafSize,
) -> HashValue<CS> {
    let node = nodes[index.node_index()].as_ref();
    let payload = match index.node_type() {
        NodeType::Leaf(_) => {
            let kp = node.and_then(|node| match node {
                Node::Leaf(kp) => Some(kp.clone()),
                Node::Parent(_) => None,
            });
            LeafNodeHashInput {
                node_index: index,
                key_package: kp,
            }
            .get_encoding()
        }
        NodeType::Parent(pindex) => {
            let parent_node = node.and_then(|node| match node {
                Node::Leaf(_) => None,
                Node::Parent(pn) => Some(pn.clone()),
            });
            let left_hash = node_hash(nodes, pindex.left(), leaf_size);
            let right_hash = node_hash(nodes, pindex.right(leaf_size), leaf_size);
            ParentNodeHashInput {
                node_index: index,
                parent_node,
                left_hash,
                right_hash,
            }
            .get_encoding()
        }
    };
    CS::hash(&payload)
}
