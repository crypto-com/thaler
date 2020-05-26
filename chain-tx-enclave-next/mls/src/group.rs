use crate::extensions::{self as ext};
use crate::keypackage::Timespec;
use crate::keypackage::{self as kp, KeyPackage, OwnedKeyPackage};
use crate::message::*;
use crate::tree::*;
use ra_client::EnclaveCertVerifier;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub struct EpochSecrets {}
impl EpochSecrets {
    pub fn generate_new_epoch_secrets(
        &self,
        _commit_secret: Vec<u8>,
        _updated_group_context: &GroupContext,
    ) -> Self {
        todo!()
    }

    pub fn compute_confirmation(&self, _confirmed_transcript: &[u8]) -> Vec<u8> {
        todo!()
    }
}

/// auxiliary structure to hold group context + tree
pub struct GroupAux {
    pub context: GroupContext,
    pub tree: Tree,
    pub secrets: EpochSecrets,
    pub owned_kp: OwnedKeyPackage,
}

impl GroupAux {
    fn new(context: GroupContext, tree: Tree, owned_kp: OwnedKeyPackage) -> Self {
        GroupAux {
            context,
            tree,
            secrets: EpochSecrets {},
            owned_kp,
        }
    }

    fn add_init(&mut self, _kp: &KeyPackage) -> MLSPlaintext {
        todo!()
    }

    fn get_confirmed_transcript_hash(&self, _commit: &Commit) -> Vec<u8> {
        todo!()
    }

    fn get_signed_commit(&self, _plain: &MLSPlaintextCommon) -> MLSPlaintext {
        todo!()
    }

    fn get_welcome_msg(&self) -> Welcome {
        todo!()
    }

    fn init_commit(&mut self, add_proposals: &[MLSPlaintext]) -> (MLSPlaintext, Welcome) {
        let add_proposals_ids: Vec<ProposalId> = vec![]; //todo!();
        let mut updated_tree = self.tree.clone();
        updated_tree.update(&add_proposals, &[], &[]);
        let commit_secret = vec![0; self.tree.cs.hash_len()];
        let commit = Commit {
            updates: vec![],
            removes: vec![],
            adds: add_proposals_ids,
            path: None,
        };
        let updated_epoch = self.context.epoch + 1;
        let confirmed_transcript_hash = self.get_confirmed_transcript_hash(&commit);
        let mut updated_group_context = self.context.clone();
        updated_group_context.epoch = updated_epoch;
        updated_group_context.tree_hash = updated_tree.compute_tree_hash();
        updated_group_context.confirmed_transcript_hash = confirmed_transcript_hash;
        let epoch_secrets = self
            .secrets
            .generate_new_epoch_secrets(commit_secret, &updated_group_context);
        let confirmation =
            epoch_secrets.compute_confirmation(&updated_group_context.confirmed_transcript_hash);
        let sender = Sender {
            sender_type: SenderType::Member,
            sender: 0, // FIXME
        };
        let commit_content = MLSPlaintextCommon {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender,
            content: ContentType::Commit {
                commit,
                confirmation,
            },
        };
        (
            self.get_signed_commit(&commit_content),
            self.get_welcome_msg(),
        )
    }

    pub fn init_group(
        creator_kp: OwnedKeyPackage,
        others: &[KeyPackage],
        ra_verifier: &EnclaveCertVerifier,
        genesis_time: Timespec,
    ) -> Result<(Self, Vec<MLSPlaintext>, MLSPlaintext, Welcome), kp::Error> {
        let mut kps = BTreeSet::new();
        for kp in others.iter() {
            if kps.contains(kp) {
                return Err(kp::Error::DuplicateKeyPackage);
            } else {
                kp.verify(&ra_verifier, genesis_time)?;
                kps.insert(kp.clone());
            }
        }
        if kps.contains(&creator_kp.keypackage) {
            Err(kp::Error::DuplicateKeyPackage)
        } else {
            creator_kp.keypackage.verify(&ra_verifier, genesis_time)?;
            let (context, tree) = GroupContext::init(creator_kp.keypackage.clone())?;
            let mut group = GroupAux::new(context, tree, creator_kp);
            let add_proposals: Vec<MLSPlaintext> =
                others.iter().map(|kp| group.add_init(kp)).collect();
            let (commit, welcome) = group.init_commit(&add_proposals);
            Ok((group, add_proposals, commit, welcome))
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(Clone)]
pub enum CipherSuite {
    MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 = 2,
}

impl CipherSuite {
    /// TODO: use generic array?
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => Sha256::digest(data).to_vec(),
        }
    }

    pub fn hash_len(&self) -> usize {
        match self {
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => 32,
        }
    }
}

const TDBE_GROUP_ID: &[u8] = b"Crypto.com Chain Council Node Transaction Data Bootstrap Enclave";

/// spec: draft-ietf-mls-protocol.md#group-state
#[derive(Clone)]
pub struct GroupContext {
    /// 0..255 bytes -- application-defined id
    pub group_id: Vec<u8>,
    /// version of the group key
    /// (incremented by 1 for each Commit message
    /// that is processed)
    pub epoch: u64,
    /// commitment to the contents of the
    /// group's ratchet tree and the credentials
    /// for the members of the group
    /// 0..255
    pub tree_hash: Vec<u8>,
    /// field contains a running hash over
    /// the messages that led to this state.
    /// 0..255
    pub confirmed_transcript_hash: Vec<u8>,
    pub extensions: Vec<ext::ExtensionEntry>,
}

impl GroupContext {
    pub fn init(creator_kp: KeyPackage) -> Result<(Self, Tree), kp::Error> {
        let extensions = creator_kp.payload.extensions.clone();
        let tree = Tree::init(creator_kp)?;
        Ok((
            GroupContext {
                group_id: TDBE_GROUP_ID.to_vec(),
                epoch: 0,
                tree_hash: tree.compute_tree_hash(),
                confirmed_transcript_hash: vec![],
                extensions,
            },
            tree,
        ))
    }
}
