use crate::ciphersuite::CipherSuite;
use crate::key::HPKEPublicKey;
use crate::keypackage::{
    self as kp, KeyPackage, Timespec, MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
};
use crate::message::*;
use crate::tree_math::{LeafSize, NodeSize};
use crate::utils::{decode_option, encode_option, encode_vec_u32, read_vec_u32};
use ra_client::AttestedCertVerifier;
use rustls::internal::msgs::codec::{self, Codec, Reader};

#[derive(Debug, Clone)]
/// spec: draft-ietf-mls-protocol.md#tree-hashes
pub struct ParentNode {
    pub public_key: HPKEPublicKey,
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
        let public_key = HPKEPublicKey::read(r)?;
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

impl Tree {
    pub fn get_package(&self, leaf_index: LeafSize) -> Option<&KeyPackage> {
        match self.nodes[NodeSize::from_leaf_index(leaf_index).0] {
            Node::Leaf(Some(ref pk)) => Some(pk),
            _ => None,
        }
    }

    pub fn from_group_info(
        my_pos: usize,
        cs: CipherSuite,
        group_info_nodes: &[Option<Node>],
    ) -> Result<Self, kp::Error> {
        let mut nodes = Vec::with_capacity(group_info_nodes.len());
        for (i, node) in group_info_nodes.iter().enumerate() {
            match (i % 2, node) {
                (_, Some(node)) => {
                    nodes.push(node.clone());
                }
                (0, None) => {
                    nodes.push(Node::Leaf(None));
                }
                (1, None) => {
                    nodes.push(Node::Parent(None));
                }
                _ => {}
            }
        }
        // FIXME: generate path secrets
        Ok(Self { nodes, cs, my_pos })
    }

    pub fn integrity_check(
        nodes: &[Option<Node>],
        ra_verifier: &impl AttestedCertVerifier,
        time: Timespec,
        _cs: CipherSuite,
    ) -> Result<(), kp::Error> {
        let leaf_len =
            LeafSize::from_nodes(NodeSize(nodes.len())).ok_or(kp::Error::TreeIntegrityError)?;
        for (i, node) in nodes.iter().enumerate() {
            let x = NodeSize(i);
            match node {
                Some(Node::Leaf(Some(kp))) => {
                    // leaf should be even position
                    if i % 2 != 0 {
                        return Err(kp::Error::TreeIntegrityError);
                    }
                    // "For each non-empty leaf node, verify the signature on the KeyPackage."
                    if let Err(e) = kp.verify(ra_verifier, time) {
                        return Err(e);
                    }
                }
                Some(Node::Parent(Some(_pn))) => {
                    // "For each non-empty parent node, verify that exactly one of the node's children are non-empty
                    // and have the hash of this node set as their parent_hash value (if the child is another parent)
                    // or has a parent_hash extension in the KeyPackage containing the same value (if the child is a leaf)."
                    let left_pos = x.left().unwrap();
                    let right_pos = x.right(leaf_len).unwrap();
                    if right_pos.0 >= nodes.len() {
                        return Err(kp::Error::TreeIntegrityError);
                    }
                    // FIXME: compute hash + check
                    match (&nodes[left_pos.0], &nodes[right_pos.0]) {
                        (None, Some(_right)) => {}
                        (Some(_left), None) => {}
                        _ => {
                            return Err(kp::Error::TreeIntegrityError);
                        }
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
        let node = &self.nodes[index.0];
        match node {
            Node::Leaf(kp) => {
                let mut inp = Vec::new();
                LeafNodeHashInput {
                    node_index: index.0 as u32,
                    key_package: kp.clone(),
                }
                .encode(&mut inp);
                self.cs.hash(&inp)
            }
            Node::Parent(pn) => {
                let left_index = index.left().unwrap();
                let left_hash = self.node_hash(left_index);
                let right_index = index.right(self.leaf_len()).unwrap();
                let right_hash = self.node_hash(right_index);
                let mut inp = Vec::new();
                ParentNodeHashInput {
                    node_index: index.0 as u32,
                    parent_node: pn.clone(),
                    left_hash,
                    right_hash,
                }
                .encode(&mut inp);
                self.cs.hash(&inp)
            }
        }
    }

    fn leaf_len(&self) -> LeafSize {
        LeafSize::from_nodes(NodeSize(self.nodes.len())).expect("invalid node count")
    }

    pub fn compute_tree_hash(&self) -> Vec<u8> {
        let root_index = NodeSize::root(self.leaf_len());
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
