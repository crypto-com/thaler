use crate::ciphersuite::{CipherSuite, HkdfExt};
use crate::tree_math::{LeafSize, NodeSize};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretVec};
use sha2::digest::{generic_array, BlockInput, FixedOutput, Input, Reset};
use std::marker::PhantomData;

/// "Application Secret Tree" in specs
/// treeBaseKeySource in ref impl
struct TreeBaseKeySource<D: Input + BlockInput + FixedOutput + Reset + Default + Clone> {
    pub secrets: Vec<Option<SecretVec<u8>>>,
    pub marker: PhantomData<D>,
}

impl<D: Input + BlockInput + FixedOutput + Reset + Default + Clone> TreeBaseKeySource<D> {
    /// astree_node_[root]_secret = application_secret
    pub fn new(application_secret: SecretVec<u8>, leaf_count: LeafSize) -> Self {
        let root_index = NodeSize::root(leaf_count);
        let node_len = NodeSize::node_width(leaf_count);
        let mut secrets = Vec::with_capacity(node_len.0);
        for _ in 0..node_len.0 {
            secrets.push(None);
        }
        secrets[root_index.0] = Some(application_secret);
        Self {
            secrets,
            marker: PhantomData,
        }
    }

    pub fn get_base_secret(
        &mut self,
        group_context_hash: Vec<u8>,
        sender_leaf: LeafSize,
    ) -> SecretVec<u8> {
        let node_index = NodeSize::from_leaf_index(sender_leaf);
        let leaf_count =
            LeafSize::from_nodes(NodeSize(self.secrets.len())).expect("invalid node count");
        let d = node_index.direct_path(leaf_count);
        let mut found_i = None;
        for (i, node) in d.iter().enumerate() {
            if self.secrets[node.0].is_some() {
                found_i = Some(i);
                break;
            }
        }
        use generic_array::typenum::Unsigned;
        let secret_len = D::OutputSize::to_u16();
        for node in d[..found_i.unwrap()].iter().rev() {
            let l = node.left().expect("should have left");
            let r = node.right(leaf_count).expect("should have right");
            let secret = self.secrets[node.0].take().unwrap();
            let skdf = Hkdf::<D>::new(None, secret.expose_secret());

            self.secrets[l.0] = Some(SecretVec::new(
                skdf.derive_app_secret(
                    group_context_hash.clone(),
                    "tree",
                    l.0 as u32,
                    0,
                    secret_len,
                )
                .expect("left"),
            ));
            self.secrets[r.0] = Some(SecretVec::new(
                skdf.derive_app_secret(
                    group_context_hash.clone(),
                    "tree",
                    r.0 as u32,
                    0,
                    secret_len,
                )
                .expect("right"),
            ));
            // secretvec should implement zeroize on drop
            // since it's take(), the value should be implicitly dropped; this is just an explicit call for clarity
            drop(secret);
        }

        self.secrets[node_index.0].take().expect("sender secret")
    }
}

struct HashRatchet {
    pub node: NodeSize,
    pub next_secret: SecretVec<u8>,
    pub next_gen: u32,
}

impl HashRatchet {
    pub fn new(node: NodeSize, base_secret: SecretVec<u8>) -> Self {
        Self {
            node,
            next_secret: base_secret,
            next_gen: 0,
        }
    }

    /// spec: draft-ietf-mls-protocol.md#encryption-keys
    pub fn next<D: Input + BlockInput + FixedOutput + Reset + Default + Clone>(
        &mut self,
        group_context_hash: Vec<u8>,
        cs: CipherSuite,
    ) -> (SecretVec<u8>, Vec<u8>) {
        let app_start_secret = Hkdf::<D>::new(None, self.next_secret.expose_secret());

        // NOTE: in reference implementation, these were prefixed with "app-": "app-key", "app-nonce", "app-secret"
        // but it seems to be without it in the spec?
        let key = SecretVec::new(
            app_start_secret
                .derive_app_secret(
                    group_context_hash.clone(),
                    "key",
                    self.node.0 as u32,
                    self.next_gen,
                    cs.aead_key_len() as u16,
                )
                .expect("key"),
        );
        let nonce = app_start_secret
            .derive_app_secret(
                group_context_hash.clone(),
                "nonce",
                self.node.0 as u32,
                self.next_gen,
                cs.aead_nonce_len() as u16,
            )
            .expect("nonce");
        use generic_array::typenum::Unsigned;
        let secret_len = D::OutputSize::to_u16();
        let mut secret = SecretVec::new(
            app_start_secret
                .derive_app_secret(
                    group_context_hash,
                    "secret",
                    self.node.0 as u32,
                    self.next_gen,
                    secret_len,
                )
                .expect("secret"),
        );
        std::mem::swap(&mut secret, &mut self.next_secret);
        drop(secret);
        self.next_gen += 1;
        (key, nonce)
    }
}

/// ratcheting from "ASTree" secret
/// spec: draft-ietf-mls-protocol.md#encryption-keys
/// + draft-ietf-mls-protocol.md#astree
pub struct GroupKeySource<D: Input + BlockInput + FixedOutput + Reset + Default + Clone> {
    ratchets: Vec<Option<HashRatchet>>,
    base_secret_source: TreeBaseKeySource<D>,
}

impl<D: Input + BlockInput + FixedOutput + Reset + Default + Clone> GroupKeySource<D> {
    pub fn new(application_secret: SecretVec<u8>, leaf_count: LeafSize) -> Self {
        let base_secret_source = TreeBaseKeySource::new(application_secret, leaf_count);
        let mut ratchets = Vec::with_capacity(leaf_count.0);
        for _ in 0..leaf_count.0 {
            ratchets.push(None);
        }
        Self {
            base_secret_source,
            ratchets,
        }
    }

    pub fn get_key_nonce(
        &mut self,
        group_context_hash: Vec<u8>,
        sender_leaf: LeafSize,
        cs: CipherSuite,
    ) -> (SecretVec<u8>, Vec<u8>) {
        if self.ratchets[sender_leaf.0].is_none() {
            let base_secret = self
                .base_secret_source
                .get_base_secret(group_context_hash.clone(), sender_leaf);
            self.ratchets[sender_leaf.0] = Some(HashRatchet::new(
                NodeSize::from_leaf_index(sender_leaf),
                base_secret,
            ));
        };
        let ratchet = self.ratchets[sender_leaf.0].as_mut().unwrap();
        ratchet.next::<D>(group_context_hash, cs)
    }
}
