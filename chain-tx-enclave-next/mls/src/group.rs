use std::collections::{BTreeMap, BTreeSet};

use ra_client::AttestedCertVerifier;
use rustls::internal::msgs::codec::{Codec, Reader};
use secrecy::{ExposeSecret, Secret, Zeroize};
use subtle::ConstantTimeEq;

use crate::ciphersuite::{CipherSuite, HashValue, SecretValue};
use crate::crypto::{encrypt_group_info, open_group_info, open_group_secret, seal_group_secret};
use crate::error::{
    CommitError, FindExtensionError, InitGroupError, KeyPackageError, ProcessWelcomeError,
};
use crate::extensions::{self as ext, ExtensionType, MLSExtension};
use crate::key::{IdentityPrivateKey, IdentityPublicKey};
use crate::keypackage::{
    find_extension, verify_keypackage_and_secrets, KeyPackage, KeyPackageSecret, Timespec,
    PROTOCOL_VERSION_MLS10,
};
use crate::message::{
    self, Add, Commit, CommitContent, ContentType, GroupContext, GroupSecret, MLSPlaintext,
    MLSPlaintextCommon, MLSPlaintextTBS, PathSecret, Proposal, ProposalId, Remove, Sender,
    SenderType, Update, UpdatePath, Welcome,
};
use crate::secrets::EpochSecrets;
use crate::tree::{Node, RatchetTreeExt, TreeEvolveResult, TreePublicKey, TreeSecret};
use crate::tree_math::{LeafSize, NodeSize, NodeType, ParentSize};
use crate::utils;
use crate::utils::{encode_vec_u8_u16, encode_vec_u8_u8, read_vec_u8_u16, read_vec_u8_u8};

impl<CS: CipherSuite> GroupContext<CS> {
    pub fn new(tree: &TreePublicKey<CS>) -> Self {
        let extensions = tree
            .get_package(LeafSize(0))
            .expect("init tree has first leaf node")
            .payload
            .extensions
            .clone();
        Self {
            group_id: TDBE_GROUP_ID.to_vec(),
            epoch: 0,
            tree_hash: tree.compute_tree_hash(),
            confirmed_transcript_hash: HashValue::default(),
            extensions,
        }
    }
}

/// auxiliary structure to hold group context + tree
pub struct GroupAux<CS: CipherSuite> {
    // public and shared
    pub context: GroupContext<CS>,
    pub tree: TreePublicKey<CS>,
    pub interim_transcript_hash: Option<HashValue<CS>>,

    // public and specific to current participant
    /// position of the participant in the tree
    pub my_pos: LeafSize,

    // secrets
    pub tree_secret: TreeSecret<CS>,
    pub secrets: EpochSecrets<CS>,
    /// secrets for the leaf keypackage
    pub kp_secret: KeyPackageSecret<CS>,

    // secrets for pending commits and updates
    /// record the pending credential secret for self-update proposals.
    /// inserted when commit self update proposal, removed when processing the commit.
    pub pending_updates: BTreeMap<ProposalId<CS>, IdentityPrivateKey>,
    /// record the new init private key generate in commit.
    /// inserted when commit proposals, removed when processing self commit.
    pub pending_commit: BTreeMap<ProposalId<CS>, Secret<SecretValue<CS>>>,
}

impl<CS: CipherSuite + Ord> GroupAux<CS> {
    fn new(
        context: GroupContext<CS>,
        tree: TreePublicKey<CS>,
        my_pos: LeafSize,
        kp_secret: KeyPackageSecret<CS>,
    ) -> Result<Self, hkdf::InvalidLength> {
        let secrets = EpochSecrets::new(&context.get_encoding());
        Ok(GroupAux {
            context,
            tree,
            interim_transcript_hash: None,
            my_pos,
            tree_secret: TreeSecret::default(),
            secrets,
            kp_secret,
            pending_updates: BTreeMap::new(),
            pending_commit: BTreeMap::new(),
        })
    }

    fn get_sender(&self) -> Sender {
        Sender {
            sender_type: SenderType::Member,
            sender: self.my_pos,
        }
    }

    /// Generate and sign add proposal
    pub fn get_signed_add(
        &self,
        key_package: KeyPackage<CS>,
    ) -> Result<MLSPlaintext<CS>, ring::error::Unspecified> {
        let sender = self.get_sender();
        let add_content = MLSPlaintextCommon {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender,
            authenticated_data: vec![],
            content: ContentType::Proposal(Proposal::Add(Add { key_package })),
        };
        let to_be_signed = MLSPlaintextTBS {
            context: self.context.clone(),
            content: add_content.clone(),
        }
        .get_encoding();
        let signature = self.kp_secret.credential_private_key.sign(&to_be_signed)?;
        Ok(MLSPlaintext {
            content: add_content,
            signature,
        })
    }

    /// Update self keypackage and sign update proposal
    ///
    /// The secret will be stored tempararily, and take effect when processing the commit.
    pub fn get_signed_self_update(
        &mut self,
        key_package: KeyPackage<CS>,
        secret: KeyPackageSecret<CS>,
    ) -> Result<MLSPlaintext<CS>, ring::error::Unspecified> {
        let sender = self.get_sender();
        let content = MLSPlaintextCommon {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender,
            authenticated_data: vec![],
            content: ContentType::Proposal(Proposal::Update(Update { key_package })),
        };
        let to_be_signed = MLSPlaintextTBS {
            context: self.context.clone(),
            content: content.clone(),
        }
        .get_encoding();
        let signature = self.kp_secret.credential_private_key.sign(&to_be_signed)?;
        let proposal = MLSPlaintext { content, signature };
        let proposal_id = ProposalId(CS::hash(&proposal.get_encoding()));
        self.pending_updates
            .insert(proposal_id, secret.credential_private_key);
        Ok(proposal)
    }

    /// Generate and sign remove proposal
    ///
    /// # Arguments
    ///
    /// * `to_remove` - The leaf index to be removed
    pub fn get_signed_remove(
        &self,
        removed: LeafSize,
    ) -> Result<MLSPlaintext<CS>, ring::error::Unspecified> {
        let sender = self.get_sender();
        let add_content = MLSPlaintextCommon {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender,
            authenticated_data: vec![],
            content: ContentType::Proposal(Proposal::Remove(Remove { removed })),
        };
        let to_be_signed = MLSPlaintextTBS {
            context: self.context.clone(),
            content: add_content.clone(),
        }
        .get_encoding();
        let signature = self.kp_secret.credential_private_key.sign(&to_be_signed)?;
        Ok(MLSPlaintext {
            content: add_content,
            signature,
        })
    }

    /// spec: draft-ietf-mls-protocol.md#group-state
    fn new_confirmed_transcript_hash(&self, sender: Sender, commit: &Commit<CS>) -> HashValue<CS> {
        let content_to_commit = message::MLSPlaintextCommitContent::new(
            self.context.group_id.clone(),
            self.context.epoch,
            sender,
            commit.clone(),
        )
        .get_encoding();
        let to_hash = [
            // spec: When a new group is created, the `interim_transcript_hash` field is set to the
            // zero-length octet string,
            // which is the `None` case here.
            self.interim_transcript_hash
                .as_ref()
                .map(|h| h.as_ref())
                .unwrap_or(b""),
            &content_to_commit,
        ]
        .concat();
        CS::hash(&to_hash)
    }

    /// spec: draft-ietf-mls-protocol.md#group-state
    fn new_interim_transcript_hash(
        &self,
        commit_confirmation: HashValue<CS>,
        commit_msg_sig: Vec<u8>,
        confirmed_transcript: HashValue<CS>,
    ) -> HashValue<CS> {
        let commit_auth = message::MLSPlaintextCommitAuthData {
            confirmation_tag: commit_confirmation,
            signature: commit_msg_sig,
        }
        .get_encoding();
        CS::hash(&[confirmed_transcript.as_ref(), &commit_auth].concat())
    }

    fn get_signed_commit(
        &self,
        plain: &MLSPlaintextCommon<CS>,
    ) -> Result<MLSPlaintext<CS>, ring::error::Unspecified> {
        let to_be_signed = MLSPlaintextTBS {
            context: self.context.clone(), // TODO: current or next context?
            content: plain.clone(),
        }
        .get_encoding();

        let signature = self.kp_secret.credential_private_key.sign(&to_be_signed)?;
        Ok(MLSPlaintext {
            content: plain.clone(),
            signature,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn get_welcome_msg(
        &self,
        updated_tree: TreePublicKey<CS>,
        updated_group_context: &GroupContext<CS>,
        updated_secrets: &EpochSecrets<CS>,
        confirmation_tag: HashValue<CS>,
        interim_transcript_hash: HashValue<CS>,
        positions: Vec<(LeafSize, KeyPackage<CS>)>,
        tree_secret: &TreeSecret<CS>,
    ) -> Result<Welcome<CS>, CommitError> {
        let mut secrets = Vec::with_capacity(positions.len());
        for (position, key_package) in positions.iter() {
            let overlap = ParentSize::common_ancestor(self.my_pos, *position)
                .ok_or(CommitError::CommitSelfAdd)?;
            let direct_path = NodeSize::from(self.my_pos).direct_path(updated_tree.leaf_len());
            let overlap_pos = direct_path
                .iter()
                .position(|&p| p == overlap)
                .expect("impossible, overlap must in the direct path of my_pos");
            // FIXME it's only correct when new empty nodes are extension of old direct_path.
            // https://github.com/crypto-com/chain/issues/2087
            let path_secret: Option<PathSecret<CS>> = tree_secret
                .path_secrets
                .get(overlap_pos)
                .map(|secret| PathSecret {
                    path_secret: secret.clone(),
                });
            let group_secret = GroupSecret {
                joiner_secret: updated_secrets.joiner_secret.clone(),
                path_secret,
            };

            let encrypted_group_secret = seal_group_secret(&group_secret, key_package)?; // FIXME: &self.context ?
            secrets.push(encrypted_group_secret);
        }

        let tree_hash = updated_tree.compute_tree_hash();
        let mut extensions = updated_group_context.extensions.clone();
        extensions.push(RatchetTreeExt::<CS>::new(updated_tree.nodes).entry());
        let group_info_p = GroupInfoPayload {
            group_id: updated_group_context.group_id.clone(),
            epoch: updated_group_context.epoch,
            tree_hash,
            confirmed_transcript_hash: updated_group_context.confirmed_transcript_hash.clone(),
            interim_transcript_hash,
            extensions, // FIXME: gen new keypackage + extension with parent hash?
            confirmation_tag,
            signer_index: self.my_pos,
        };
        let signature = self
            .kp_secret
            .credential_private_key
            .sign(&group_info_p.get_encoding())?;
        let group_info = GroupInfo {
            payload: group_info_p,
            signature,
        };
        let (mut welcome_key, welcome_nonce) = updated_secrets.get_welcome_secret_key_nonce();
        let encrypted_group_info =
            encrypt_group_info::<CS>(&group_info, &welcome_key, &welcome_nonce)?;
        welcome_key.as_mut().zeroize();

        Ok(Welcome {
            version: PROTOCOL_VERSION_MLS10,
            cipher_suite: CS::tag(),
            secrets,
            encrypted_group_info,
        })
    }

    /// generates `confirmation_tag =
    /// KDF.Extract(confirmation_key, GroupContext.confirmed_transcript_hash)`
    /// plus returns the corresponding updated_group_context and epoch secrets
    pub(crate) fn generate_commit_confirmation(
        &self,
        commit: &Commit<CS>,
        updated_tree: &TreePublicKey<CS>,
        tree_secret: Option<&TreeSecret<CS>>,
    ) -> (HashValue<CS>, GroupContext<CS>, EpochSecrets<CS>) {
        let updated_epoch = self.context.epoch + 1;
        let confirmed_transcript_hash =
            self.new_confirmed_transcript_hash(self.get_sender(), &commit);
        let updated_group_context = GroupContext {
            tree_hash: updated_tree.compute_tree_hash(),
            epoch: updated_epoch,
            confirmed_transcript_hash,
            ..self.context.clone()
        };

        // If not populating the `path` field: ... Define `commit_secret` as the all-zero vector of the same
        // length as a `path_secret` value would be.
        let empty_commit_secret = Secret::new(SecretValue::<CS>::default());
        let commit_secret = tree_secret
            .map(|secret| &secret.update_secret)
            .unwrap_or(&empty_commit_secret);

        let epoch_secrets = EpochSecrets::<CS>::generate(
            self.secrets.init_secret.expose_secret(),
            commit_secret.expose_secret(),
            &updated_group_context.get_encoding(),
        );
        let confirmation_tag =
            epoch_secrets.compute_confirmation(&updated_group_context.confirmed_transcript_hash);
        (confirmation_tag, updated_group_context, epoch_secrets)
    }

    /// Generate commit message for proposals.
    fn do_commit_proposals(
        &self,
        proposals: &[MLSPlaintext<CS>],
    ) -> Result<CommitProposalResult<CS>, CommitError> {
        // split proposals by types
        let mut proposal_ids: Vec<ProposalId<CS>> = Vec::new();
        let mut additions: Vec<Add<CS>> = Vec::new();
        let mut updates: Vec<(LeafSize, Update<CS>, ProposalId<CS>)> = Vec::new();
        let mut removes: Vec<Remove> = Vec::new();
        for p in proposals.iter() {
            let proposal_id = ProposalId(CS::hash(&p.get_encoding()));
            match &p.content.content {
                ContentType::Proposal(Proposal::Add(add)) => {
                    proposal_ids.push(proposal_id);
                    additions.push(add.clone());
                }
                ContentType::Proposal(Proposal::Update(update)) => {
                    proposal_ids.push(proposal_id.clone());
                    updates.push((p.content.sender.sender, update.clone(), proposal_id));
                }
                ContentType::Proposal(Proposal::Remove(remove)) => {
                    proposal_ids.push(proposal_id);
                    removes.push(remove.clone());
                }
                _ => panic!("invalid proposal message type"),
            }
        }

        let mut updated_tree = self.tree.clone();
        let positions = updated_tree.update(&additions, &updates, &removes)?;

        let self_update_proposal = updates
            .iter()
            .find(|(sender, _, _)| *sender == self.my_pos)
            .map(|(_, _, proposal_id)| proposal_id);
        let credential_private_key = if let Some(proposal_id) = self_update_proposal {
            self.pending_updates
                .get(&proposal_id)
                .ok_or(CommitError::PendingCredentialPrivateKeyNotFound)?
        } else {
            &self.kp_secret.credential_private_key
        };

        // pathRequired = isGenesisInit || haveUpdateOrRemove || haveNoProposalsAtAll
        let should_populate_path =
            proposals.is_empty() || !updates.is_empty() || !removes.is_empty();

        let (path, tree_secret, leaf_secret) = if should_populate_path {
            // new init key
            let leaf_secret = updated_tree
                .get_package_mut(self.my_pos)
                .expect("my keypackage not exists")
                .update_init_key();

            // update path secrets
            let TreeEvolveResult {
                path_nodes,
                leaf_parent_hash,
                tree_secret,
            } = updated_tree.evolve(&self.context.get_encoding(), self.my_pos, &leaf_secret)?;

            let kp = updated_tree
                .get_package_mut(self.my_pos)
                .expect("my keypackage not exists");
            // update keypackage's parent_hash extension
            kp.payload
                .put_extension(&ext::ParentHashExt(leaf_parent_hash));
            kp.update_signature(credential_private_key)?;
            (
                Some(UpdatePath {
                    leaf_key_package: kp.clone(),
                    nodes: path_nodes,
                }),
                Some(tree_secret),
                Some(leaf_secret),
            )
        } else {
            (None, None, None)
        };

        let commit = Commit {
            proposals: proposal_ids,
            path,
        };

        let (confirmation_tag, updated_group_context, epoch_secrets) =
            self.generate_commit_confirmation(&commit, &updated_tree, tree_secret.as_ref());
        let sender = self.get_sender();
        let commit_content = MLSPlaintextCommon {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender,
            authenticated_data: vec![],
            content: ContentType::Commit {
                commit,
                confirmation_tag: confirmation_tag.clone(),
            },
        };
        let signed_commit = self.get_signed_commit(&commit_content)?;
        let interim_transcript_hash = self.new_interim_transcript_hash(
            confirmation_tag.clone(),
            signed_commit.signature.clone(),
            updated_group_context.confirmed_transcript_hash.clone(),
        );

        Ok(CommitProposalResult {
            commit: signed_commit,
            welcome: self.get_welcome_msg(
                updated_tree,
                &updated_group_context,
                &epoch_secrets,
                confirmation_tag,
                interim_transcript_hash,
                positions,
                tree_secret.as_ref().unwrap_or(&self.tree_secret),
            )?,
            leaf_secret,
        })
    }

    /// commit proposals
    pub fn commit_proposals(
        &mut self,
        proposals: &[MLSPlaintext<CS>],
    ) -> Result<(MLSPlaintext<CS>, Welcome<CS>), CommitError> {
        let CommitProposalResult {
            commit,
            welcome,
            leaf_secret,
        } = self.do_commit_proposals(proposals)?;
        if let Some(leaf_secret) = leaf_secret {
            self.pending_commit
                .insert(ProposalId(CS::hash(&commit.get_encoding())), leaf_secret);
        }
        Ok((commit, welcome))
    }

    fn verify_msg_signature(
        &self,
        msg: &MLSPlaintext<CS>,
        ra_verifier: &impl AttestedCertVerifier,
        now: Timespec,
    ) -> Result<(), CommitError> {
        let kp = self
            .tree
            .get_package(msg.content.sender.sender)
            .ok_or(CommitError::SenderNotFound)?;
        let pk = IdentityPublicKey::new_unsafe(kp.verify(ra_verifier, now)?.public_key.to_vec());
        Ok(msg.verify_signature(&self.context, &pk)?)
    }

    pub fn process_commit(
        &mut self,
        commit: MLSPlaintext<CS>,
        proposals: &[MLSPlaintext<CS>],
        ra_verifier: &impl AttestedCertVerifier,
        now: Timespec,
    ) -> Result<(), CommitError> {
        // "Verify that the epoch field of the enclosing MLSPlaintext message
        // is equal to the epoch field of the current GroupContext object"
        if self.context.epoch != commit.content.epoch {
            return Err(CommitError::GroupEpochError);
        }

        // "Verify that the signature on the MLSPlaintext message verifies
        //  using the public key from the credential stored at the leaf in the tree indicated by the sender field."
        self.verify_msg_signature(&commit, ra_verifier, now)?;
        for proposal in proposals.iter() {
            self.verify_msg_signature(&proposal, ra_verifier, now)?;
        }

        // "Generate a provisional GroupContext object by applying the proposals referenced in the commit object..."
        let commit_content = CommitContent::new(&commit, proposals)
            .map_err(|_| CommitError::InvalidCommitMessage)?;

        // update credential_private_key for self updating proposal
        let self_update_proposal = commit_content
            .updates
            .iter()
            .find(|(sender, _, _)| *sender == self.my_pos);
        let credential_private_key = if let Some((_, _, proposal_id)) = self_update_proposal {
            // apply the pending credential_private_key
            self.pending_updates
                .get(proposal_id)
                .ok_or(CommitError::PendingCredentialPrivateKeyNotFound)?
        } else {
            &self.kp_secret.credential_private_key
        };

        let commit_id = ProposalId(CS::hash(&commit.get_encoding()));
        let leaf_secret =
            if commit_content.commit.path.is_some() && commit_content.sender == self.my_pos {
                // apply pending `leaf_secret` if I'm the committer
                self.pending_commit
                    .get(&commit_id)
                    .ok_or(CommitError::PendingInitPrivateKeyNotFound)?
            } else {
                &self.kp_secret.leaf_secret
            };

        // verify the leaf key package in commit path
        if let Some(path) = &commit_content.commit.path {
            if commit_content.sender == self.my_pos {
                verify_keypackage_and_secrets(
                    &path.leaf_key_package,
                    leaf_secret.expose_secret(),
                    credential_private_key,
                    ra_verifier,
                    now,
                )?;
            } else {
                path.leaf_key_package.verify(ra_verifier, now)?;
            }
        }

        // check path populating condition
        let should_populate_path = (commit_content.additions.is_empty()
            && commit_content.updates.is_empty()
            && commit_content.removes.is_empty())
            || !commit_content.updates.is_empty()
            || !commit_content.removes.is_empty();
        if should_populate_path && commit_content.commit.path.is_none() {
            return Err(CommitError::CommitPathNotPopulated);
        }

        let mut tree = self.tree.clone();
        tree.update(
            &commit_content.additions,
            &commit_content.updates,
            &commit_content.removes,
        )?;
        // "If the path value is populated: Process the path value..."
        let tree_diff = if let Some(path) = &commit_content.commit.path {
            let leaf_parent_hash = tree.merge(commit_content.sender, &path.nodes);
            let tree_diff = self.tree_secret.apply_path_secrets(
                commit_content.sender,
                self.my_pos,
                &tree,
                &self.context.get_encoding(),
                &path.nodes,
                leaf_secret.expose_secret(),
            )?;
            // Verify that the KeyPackage has a `parent_hash` extension and that its value
            // matches the new parent of the sender's leaf node.
            let ext = path
                .leaf_key_package
                .payload
                .find_extension::<ext::ParentHashExt<CS>>()?;
            if !bool::from(
                ext.0
                    .unwrap_or_default()
                    .ct_eq(&leaf_parent_hash.unwrap_or_default()),
            ) {
                return Err(CommitError::LeafParentHashDontMatch);
            }

            tree.set_package(commit_content.sender, path.leaf_key_package.clone());
            Some(tree_diff)
        } else {
            None
        };

        // "Update the new GroupContext's confirmed and interim transcript hashes using the new Commit."
        let confirmed_transcript_hash = self
            .new_confirmed_transcript_hash(commit.content.sender.clone(), &commit_content.commit);

        let new_interim_transcript_hash = self.new_interim_transcript_hash(
            commit_content.confirmation_tag.clone(),
            commit.signature,
            confirmed_transcript_hash.clone(),
        );

        let updated_group_context = GroupContext {
            epoch: self.context.epoch + 1,
            tree_hash: tree.compute_tree_hash(),
            confirmed_transcript_hash,
            ..self.context.clone()
        };

        // "Use the commit_secret, the provisional GroupContext,
        // and the init secret from the previous epoch to compute the epoch secret and derived secrets for the new epoch."
        let empty_commit_secret = Secret::new(SecretValue::<CS>::default());
        let commit_secret = tree_diff
            .as_ref()
            .map(|diff| &diff.update_secret)
            .unwrap_or(&empty_commit_secret);
        let epoch_secrets = EpochSecrets::generate(
            self.secrets.init_secret.expose_secret(),
            commit_secret.expose_secret(),
            &updated_group_context.get_encoding(),
        );
        // "Use the `confirmation_key` for the new epoch to compute the confirmation tag for this message,
        // as described below, and verify that it is the same as the `confirmation_tag` field in the MLSPlaintext object."
        let confirmation_computed =
            epoch_secrets.compute_confirmation(&updated_group_context.confirmed_transcript_hash);

        let confirmation_ok: bool = commit_content
            .confirmation_tag
            .ct_eq(&confirmation_computed)
            .into();
        if !confirmation_ok {
            return Err(CommitError::GroupInfoIntegrityError);
        }

        // "If the above checks are successful, consider the updated GroupContext object as the current state of the group."
        self.context = updated_group_context;
        self.secrets = epoch_secrets;
        self.tree = tree;
        self.interim_transcript_hash = Some(new_interim_transcript_hash);
        if let Some(diff) = tree_diff {
            self.tree_secret.apply_tree_diff(diff);
        }
        // set pending credential_private_key
        if let Some((_, _, proposal_id)) = self_update_proposal {
            self.kp_secret.credential_private_key = self
                .pending_updates
                .remove(proposal_id)
                .expect("impossible, checked above");

            // clear pending secrets after one proposal committed
            self.pending_updates.clear();
        }

        // set pending init_private_key
        if commit_content.commit.path.is_some() && commit_content.sender == self.my_pos {
            self.kp_secret.leaf_secret = self
                .pending_commit
                .remove(&commit_id)
                .expect("impossible, checked above");
        }
        // clear pending commit secrets since they are invalid now
        self.pending_commit.clear();

        Ok(())
    }

    pub fn init_group(
        creator_kp: KeyPackage<CS>,
        secret: KeyPackageSecret<CS>,
        others: Vec<KeyPackage<CS>>,
        ra_verifier: &impl AttestedCertVerifier,
        genesis_time: Timespec,
    ) -> Result<InitGroupResult<CS>, InitGroupError> {
        let others_len = others.len();
        let kps = others.into_iter().collect::<BTreeSet<_>>();
        if kps.len() < others_len {
            return Err(InitGroupError::DuplicateKeyPackage);
        }
        for kp in kps.iter() {
            kp.verify(ra_verifier, genesis_time)?;
        }
        if kps.contains(&creator_kp) {
            Err(InitGroupError::DuplicateKeyPackage)
        } else {
            creator_kp.verify(ra_verifier, genesis_time)?;
            let tree = TreePublicKey::init(creator_kp);
            let context = GroupContext::new(&tree);
            let mut group = GroupAux::new(context, tree, LeafSize(0), secret)?;
            let adds: Vec<MLSPlaintext<CS>> = kps
                .into_iter()
                .map(|kp| group.get_signed_add(kp))
                .collect::<Result<_, _>>()?;
            let (commit, welcome) = group.commit_proposals(&adds)?;
            Ok(InitGroupResult {
                group,
                adds,
                commit,
                welcome,
            })
        }
    }

    pub fn init_group_from_welcome(
        my_kp: KeyPackage<CS>,
        kp_secret: KeyPackageSecret<CS>,
        welcome: Welcome<CS>,
        ra_verifier: &impl AttestedCertVerifier,
        genesis_time: Timespec,
    ) -> Result<Self, ProcessWelcomeError> {
        my_kp.verify(ra_verifier, genesis_time)?;
        if welcome.cipher_suite != my_kp.payload.cipher_suite {
            return Err(ProcessWelcomeError::CipherSuiteDontMatch);
        }
        if welcome.version != my_kp.payload.version {
            return Err(ProcessWelcomeError::VersionDontMatch);
        }
        if my_kp.payload.cipher_suite != CS::tag() {
            return Err(KeyPackageError::UnsupportedCipherSuite(my_kp.payload.cipher_suite).into());
        };
        let my_kp_hash = CS::hash(&my_kp.get_encoding());
        // * "Identify an entry in the secrets array..."
        let msecret = welcome
            .secrets
            .iter()
            .find(|s| s.key_package_hash == my_kp_hash);
        let secret = msecret.ok_or(ProcessWelcomeError::KeyPackageNotFound)?;
        // * "Decrypt the encrypted_group_secrets using HPKE..."
        let group_secret = open_group_secret(&secret, &kp_secret)?
            .ok_or(ProcessWelcomeError::InvalidGroupSecret)?;
        // * "From the joiner_secret in the decrypted GroupSecrets object, derive the welcome_secret, welcome_key, and welcome_nonce..."
        let (welcome_key, welcome_nonce) =
            CS::derive_welcome_secret(group_secret.joiner_secret.expose_secret());
        let group_info =
            open_group_info::<CS>(&welcome.encrypted_group_info, &welcome_key, &welcome_nonce)?
                .ok_or(ProcessWelcomeError::InvalidGroupInfo)?;

        // * "Verify the integrity of the ratchet tree..."
        let tree_ext = group_info.payload.find_extension::<RatchetTreeExt<CS>>()?;
        let tree = TreePublicKey::from_group_info(tree_ext.nodes, ra_verifier, genesis_time)?;

        // Verify that the tree hash of the ratchet tree matches the tree_hash field in the GroupInfo
        if !bool::from(
            group_info
                .payload
                .tree_hash
                .ct_eq(&tree.compute_tree_hash()),
        ) {
            return Err(ProcessWelcomeError::TreeHashDontMatch);
        }

        // * "Verify the signature on the GroupInfo object..."
        let signer_kp = tree
            .get_package(group_info.payload.signer_index)
            .ok_or(ProcessWelcomeError::KeyPackageNotFound)?;
        let identity_pk = IdentityPublicKey::new_unsafe(
            signer_kp
                .verify(ra_verifier, genesis_time)?
                .public_key
                .to_vec(),
        );
        let payload = group_info.payload.get_encoding();
        identity_pk
            .verify_signature(&payload, &group_info.signature)
            .map_err(KeyPackageError::SignatureVerifyError)?;

        // * "Construct a new group state using the information in the GroupInfo object..."
        // * "Identify a leaf in the tree array..."
        let my_pos = tree
            .iter_nodes()
            .filter_map(|(node_type, node)| match (node_type, node) {
                (NodeType::Leaf(index), Some(Node::Leaf(kp))) if kp == &my_kp => Some(index),
                _ => None,
            })
            .next()
            .ok_or(ProcessWelcomeError::KeyPackageNotFound)?;

        let mut tree_secret =
            TreeSecret::new(my_pos.into(), tree.leaf_len(), &kp_secret.leaf_secret)?;
        if let Some(PathSecret { path_secret, .. }) = group_secret.path_secret {
            tree_secret.apply_welcome_secret(
                group_info.payload.signer_index,
                my_pos,
                path_secret,
                &tree,
            )?;
        }

        // The presence of a `ratchet_tree` extension in a GroupInfo message does not
        // result in any changes to the GroupContext extensions for the group.
        let extensions = group_info
            .payload
            .extensions
            .iter()
            .filter(|ext| ext.etype != ExtensionType::RatchetTree)
            .cloned()
            .collect::<Vec<_>>();

        // * "Set the confirmed transcript hash in the new state to the value of the confirmed_transcript_hash in the GroupInfo."
        let context = GroupContext {
            group_id: group_info.payload.group_id.clone(),
            epoch: group_info.payload.epoch,
            tree_hash: group_info.payload.tree_hash,
            confirmed_transcript_hash: group_info.payload.confirmed_transcript_hash.clone(),
            extensions,
        };

        // * "Use the epoch_secret from the GroupSecrets object to generate the epoch secret and other derived secrets for the current epoch."
        let secrets =
            EpochSecrets::from_joiner_secret(group_secret.joiner_secret, &context.get_encoding());
        let group = GroupAux {
            context,
            tree,
            interim_transcript_hash: Some(group_info.payload.interim_transcript_hash.clone()),
            my_pos,
            tree_secret,
            kp_secret,
            secrets,
            pending_updates: BTreeMap::new(),
            pending_commit: BTreeMap::new(),
        };
        // * "Verify the confirmation tag in the GroupInfo using the derived confirmation key and the confirmed_transcript_hash from the GroupInfo."
        let confirmation_tag = group
            .secrets
            .compute_confirmation(&group.context.confirmed_transcript_hash);

        let confirmation_ok: bool = confirmation_tag
            .ct_eq(&group_info.payload.confirmation_tag)
            .into();
        if !confirmation_ok {
            return Err(ProcessWelcomeError::GroupInfoIntegrityError);
        }
        Ok(group)
    }
}

/// Result of init_group operation
pub struct InitGroupResult<CS: CipherSuite> {
    pub group: GroupAux<CS>,
    pub adds: Vec<MLSPlaintext<CS>>,
    pub commit: MLSPlaintext<CS>,
    pub welcome: Welcome<CS>,
}

pub struct CommitProposalResult<CS: CipherSuite> {
    pub commit: MLSPlaintext<CS>,
    pub welcome: Welcome<CS>,
    pub leaf_secret: Option<Secret<SecretValue<CS>>>,
}

const TDBE_GROUP_ID: &[u8] = b"Crypto.com Chain Council Node Transaction Data Bootstrap Enclave";

/// spec: draft-ietf-mls-protocol.md#Welcoming-New-Members
#[derive(Debug, Clone)]
pub struct GroupInfoPayload<CS: CipherSuite> {
    /// 0..255 bytes -- application-defined id
    pub group_id: Vec<u8>,
    /// version of the group key
    /// (incremented by 1 for each Commit message
    /// that is processed)
    pub epoch: u64,
    /// 0..255
    pub tree_hash: HashValue<CS>,
    /// 0..255
    pub confirmed_transcript_hash: HashValue<CS>,
    /// 0..255
    pub interim_transcript_hash: HashValue<CS>,
    /// 0..2^32-1
    pub extensions: Vec<ext::ExtensionEntry>,
    /// 0..255
    pub confirmation_tag: HashValue<CS>,
    pub signer_index: LeafSize,
}

impl<CS: CipherSuite> Codec for GroupInfoPayload<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_vec_u8_u8(bytes, &self.group_id);
        self.epoch.encode(bytes);
        self.tree_hash.encode(bytes);
        self.confirmed_transcript_hash.encode(bytes);
        self.interim_transcript_hash.encode(bytes);
        utils::encode_vec_u32(bytes, &self.extensions);
        self.confirmation_tag.encode(bytes);
        self.signer_index.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let group_id = read_vec_u8_u8(r)?;
        let epoch = u64::read(r)?;
        let tree_hash = HashValue::read(r)?;
        let confirmed_transcript_hash = HashValue::read(r)?;
        let interim_transcript_hash = HashValue::read(r)?;
        let extensions = utils::read_vec_u32(r)?;
        let confirmation_tag = HashValue::read(r)?;
        let signer_index = LeafSize::read(r)?;
        Some(GroupInfoPayload {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            interim_transcript_hash,
            extensions,
            confirmation_tag,
            signer_index,
        })
    }
}

impl<CS: CipherSuite> GroupInfoPayload<CS> {
    pub fn find_extension<T: MLSExtension>(&self) -> Result<T, FindExtensionError> {
        find_extension(&self.extensions)
    }
}

/// spec: draft-ietf-mls-protocol.md#Welcoming-New-Members
#[derive(Debug, Clone)]
pub struct GroupInfo<CS: CipherSuite> {
    pub payload: GroupInfoPayload<CS>,
    // 0..2^16-1
    pub signature: Vec<u8>,
}

impl<CS: CipherSuite> Codec for GroupInfo<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
        encode_vec_u8_u16(bytes, &self.signature);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let payload = GroupInfoPayload::read(r)?;
        let signature = read_vec_u8_u16(r)?;
        Some(GroupInfo { payload, signature })
    }
}

#[cfg(test)]
pub mod test {

    use super::*;
    use crate::ciphersuite::DefaultCipherSuite as CS;
    use crate::ciphersuite::GenericSecret;
    use crate::credential::Credential;
    use crate::extensions::{self as ext, MLSExtension};
    use crate::key::{derive_keypair, IdentityPrivateKey};
    use crate::keypackage::{
        KeyPackage, KeyPackagePayload, DEFAULT_CAPABILITIES_EXT, PROTOCOL_VERSION_MLS10,
    };
    use chrono::{DateTime, Utc};
    use ra_client::{
        AttestedCertVerifier, CertVerifyResult, EnclaveCertVerifierError, ENCLAVE_CERT_VERIFIER,
    };
    use rustls::internal::msgs::codec::Codec;

    #[derive(Clone)]
    pub struct MockVerifier();

    impl AttestedCertVerifier for MockVerifier {
        fn verify_attested_cert(
            &self,
            certificate: &[u8],
            _now: DateTime<Utc>,
        ) -> Result<CertVerifyResult, EnclaveCertVerifierError> {
            static VECTOR: &[u8] = include_bytes!("../tests/test_vectors/keypackage.bin");
            let kp = <KeyPackage<CS>>::read_bytes(VECTOR).expect("decode");
            let now = 1590490084;
            let t = kp.verify(&*ENCLAVE_CERT_VERIFIER, now).unwrap();

            let mut public_key = [0u8; 65];
            public_key.copy_from_slice(certificate);

            Ok(CertVerifyResult {
                public_key,
                quote: t.quote,
            })
        }
    }

    pub fn get_fake_keypackage() -> (KeyPackage<CS>, KeyPackageSecret<CS>) {
        let keypair = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        let extensions = vec![
            DEFAULT_CAPABILITIES_EXT.entry(),
            ext::LifeTimeExt::new(0, 100).entry(),
        ];

        let private_key =
            IdentityPrivateKey::from_pkcs8(keypair.as_ref()).expect("invalid private key");
        let leaf_secret = Secret::new(GenericSecret::gen());
        let (_, hpke_public) = derive_keypair(leaf_secret.expose_secret());

        let payload = KeyPackagePayload {
            version: PROTOCOL_VERSION_MLS10,
            cipher_suite: CS::tag(),
            init_key: hpke_public,
            credential: Credential::X509(private_key.public_key_raw().to_vec()),
            extensions,
        };

        // sign payload
        let signature = private_key.sign(&payload.get_encoding()).unwrap();

        (
            KeyPackage { payload, signature },
            KeyPackageSecret {
                credential_private_key: private_key,
                leaf_secret,
            },
        )
    }

    #[test]
    fn test_sign_verify_add() {
        let (creator_kp, creator_secret) = get_fake_keypackage();
        let (to_be_added, _) = get_fake_keypackage();
        let tree = TreePublicKey::new(creator_kp);
        let context = GroupContext::new(&tree);
        let group_aux = GroupAux::new(context, tree, LeafSize(0), creator_secret).unwrap();
        let plain = group_aux.get_signed_add(to_be_added).unwrap();
        assert!(plain
            .verify_signature(
                &group_aux.context,
                &group_aux.kp_secret.credential_private_key.public_key()
            )
            .is_ok());
    }

    #[test]
    fn test_welcome_commit_process() {
        let (creator_kp, creator_secret) = get_fake_keypackage();
        let (to_be_added, to_be_added_secret) = get_fake_keypackage();
        let InitGroupResult {
            mut group,
            adds,
            commit,
            welcome,
        } = GroupAux::init_group(
            creator_kp,
            creator_secret,
            vec![to_be_added.clone()],
            &MockVerifier {},
            0,
        )
        .expect("group init");
        let added_group = GroupAux::init_group_from_welcome(
            to_be_added,
            to_be_added_secret,
            welcome,
            &MockVerifier {},
            0,
        )
        .expect("group init from welcome");
        group
            .process_commit(commit, &adds, &MockVerifier {}, 0)
            .expect("commit ok");
        // they should get to the same context
        assert_eq!(&added_group.context, &group.context);
    }

    #[test]
    fn test_tree_update() {
        let (creator_kp, _) = get_fake_keypackage();
        let (to_be_added, _) = get_fake_keypackage();
        let (to_be_updated, _) = get_fake_keypackage();
        let mut tree = TreePublicKey::new(creator_kp);
        tree.update(
            &[Add {
                key_package: to_be_added.clone(),
            }],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(tree.nodes.len(), 3);
        tree.update(
            &[],
            &[(
                LeafSize(1),
                Update {
                    key_package: to_be_updated.clone(),
                },
                ProposalId(HashValue::default()),
            )],
            &[],
        )
        .unwrap();
        assert_eq!(tree.nodes.len(), 3);
        tree.update(
            &[],
            &[],
            &[Remove {
                removed: LeafSize(1),
            }],
        )
        .unwrap();
        assert_eq!(tree.nodes.len(), 3);
        assert!(tree.nodes[2].is_none());
        tree.update(
            &[Add {
                key_package: to_be_added,
            }],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(tree.nodes.len(), 3);
        assert!(!tree.nodes[2].is_none());
    }

    pub fn three_member_setup() -> (GroupAux<CS>, GroupAux<CS>, GroupAux<CS>) {
        let (member1, member1_secret) = get_fake_keypackage();
        let (member2, member2_secret) = get_fake_keypackage();
        let (member3, member3_secret) = get_fake_keypackage();
        let ra_verifier = MockVerifier {};

        // add member2 in genesis
        let InitGroupResult {
            group: mut member1_group,
            adds,
            commit,
            welcome,
        } = GroupAux::init_group(
            member1,
            member1_secret,
            vec![member2.clone()],
            &ra_verifier,
            0,
        )
        .expect("group init");

        // after commit/welcome get confirmed
        member1_group
            .process_commit(commit, &adds, &ra_verifier, 0)
            .expect("commit ok");
        let mut member2_group =
            GroupAux::init_group_from_welcome(member2, member2_secret, welcome, &ra_verifier, 0)
                .expect("group init from welcome");

        // they should get to the same context
        assert_eq!(&member1_group.context, &member2_group.context);

        // add member3
        let proposals = vec![member1_group.get_signed_add(member3.clone()).unwrap()];
        let (commit, welcome) = member1_group.commit_proposals(&proposals).unwrap();

        // after commit/welcome get confirmed
        member1_group
            .process_commit(commit.clone(), &proposals, &ra_verifier, 0)
            .expect("commit ok");
        member2_group
            .process_commit(commit, &proposals, &ra_verifier, 0)
            .expect("commit ok");
        let member3_group =
            GroupAux::init_group_from_welcome(member3, member3_secret, welcome, &ra_verifier, 0)
                .expect("group init from welcome");

        // they should get to the same context
        assert_eq!(&member1_group.context, &member2_group.context);
        assert_eq!(&member2_group.context, &member3_group.context);

        // check add result
        assert_eq!(member3_group.my_pos, LeafSize(2));
        member2_group
            .tree
            .get_package(member3_group.my_pos)
            .expect("member3 should exists");
        (member1_group, member2_group, member3_group)
    }

    #[test]
    fn test_group_update() {
        let ra_verifier = MockVerifier {};
        let (mut member1_group, mut member2_group, mut member3_group) = three_member_setup();

        // member2 do a self update
        let (member2, member2_secret) = get_fake_keypackage();
        let proposals = vec![member2_group
            .get_signed_self_update(member2.clone(), member2_secret)
            .unwrap()];
        let (commit, _welcome) = member2_group.commit_proposals(&proposals).unwrap();

        // after commit/welcome get confirmed
        member1_group
            .process_commit(commit.clone(), &proposals, &ra_verifier, 0)
            .expect("commit ok");
        member2_group
            .process_commit(commit.clone(), &proposals, &ra_verifier, 0)
            .expect("commit ok");
        member3_group
            .process_commit(commit, &proposals, &ra_verifier, 0)
            .expect("commit ok");

        // they should get to the same context
        assert_eq!(&member1_group.context, &member2_group.context);
        assert_eq!(&member2_group.context, &member3_group.context);

        // check update result
        // only check credential, because the init key is changed when commit
        assert_eq!(
            &member2_group
                .tree
                .get_package(member2_group.my_pos)
                .unwrap()
                .payload
                .credential,
            &member2.payload.credential
        );

        // remove member3
        let proposals = vec![member1_group
            .get_signed_remove(member3_group.my_pos)
            .unwrap()];
        let (commit, _welcome) = member1_group.commit_proposals(&proposals).unwrap();

        // after commit/welcome get confirmed
        member1_group
            .process_commit(commit.clone(), &proposals, &ra_verifier, 0)
            .expect("commit ok");
        member2_group
            .process_commit(commit.clone(), &proposals, &ra_verifier, 0)
            .expect("commit ok");

        // they should get to the same context
        assert_eq!(&member1_group.context, &member2_group.context);

        // check remove result
        assert_eq!(member2_group.tree.get_package(member3_group.my_pos), None);
    }

    #[test]
    fn test_invalid_commit() {
        // process invalid commit don't end up partial mutated state.
        let (member1, member1_secret) = get_fake_keypackage();
        let (member2, member2_secret) = get_fake_keypackage();
        let (member3, _member3_secret) = get_fake_keypackage();
        let ra_verifier = MockVerifier {};

        // add member2 in genesis
        let InitGroupResult {
            group: mut member1_group,
            adds,
            commit,
            welcome,
        } = GroupAux::init_group(
            member1,
            member1_secret,
            vec![member2.clone()],
            &ra_verifier,
            0,
        )
        .expect("group init");

        // after commit/welcome get confirmed
        member1_group
            .process_commit(commit, &adds, &ra_verifier, 0)
            .expect("commit ok");
        let mut member2_group =
            GroupAux::init_group_from_welcome(member2, member2_secret, welcome, &ra_verifier, 0)
                .expect("group init from welcome");

        // they should get to the same context
        assert_eq!(&member1_group.context, &member2_group.context);

        // mess up keypackage of member2
        member1_group.tree.set_package(LeafSize(1), member3);

        // add member3
        let (commit, _welcome) = member1_group.commit_proposals(&[]).unwrap();

        // after commit/welcome get confirmed
        member1_group
            .process_commit(commit.clone(), &[], &ra_verifier, 0)
            .expect("commit ok");

        // check after unsuccessful process commit, the state is not changed.
        let old_tree_hash = member2_group.tree.compute_tree_hash();
        // decryption error
        assert!(matches!(
            member2_group.process_commit(commit, &[], &ra_verifier, 0),
            Err(CommitError::HpkeError(hpke::HpkeError::InvalidTag))
        ));
        assert_eq!(old_tree_hash, member2_group.tree.compute_tree_hash());
    }
}
