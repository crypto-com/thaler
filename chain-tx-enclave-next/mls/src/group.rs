use std::collections::{BTreeMap, BTreeSet};

use crate::ciphersuite::*;
use crate::extensions as ext;
use crate::key::{HPKEPrivateKey, IdentityPrivateKey, IdentityPublicKey};
use crate::keypackage::{
    self as kp, verify_keypackage_and_secrets, KeyPackage, KeyPackageSecret, Timespec,
    PROTOCOL_VERSION_MLS10,
};
use crate::message::*;
use crate::secrets::*;
use crate::tree::*;
use crate::tree_math::{LeafSize, NodeSize};
use crate::utils::{
    encode_vec_option_u32, encode_vec_u8_u16, encode_vec_u8_u8, read_vec_option_u32,
    read_vec_u8_u16, read_vec_u8_u8,
};
use ra_client::AttestedCertVerifier;
use rustls::internal::msgs::codec::{self, Codec, Reader};
use secrecy::{ExposeSecret, SecretVec};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// auxiliary structure to hold group context + tree
pub struct GroupAux {
    pub context: GroupContext,
    pub tree: TreePublicKey,
    pub tree_secret: TreeSecret,
    pub secrets: EpochSecrets<Sha256>,
    pub kp_secret: KeyPackageSecret,

    /// record the pending credential secret for self-update proposals.
    /// inserted when commit self update proposal, removed when processing the commit.
    pub pending_updates: BTreeMap<ProposalId, IdentityPrivateKey>,
    /// record the new init private key generate in commit.
    /// inserted when commit proposals, removed when processing self commit.
    pub pending_commit: BTreeMap<ProposalId, HPKEPrivateKey>,
}

impl GroupAux {
    fn new(
        context: GroupContext,
        tree: TreePublicKey,
        kp_secret: KeyPackageSecret,
    ) -> Result<Self, hkdf::InvalidLength> {
        let secrets: EpochSecrets<Sha256> = match &tree.cs {
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                EpochSecrets::new(tree.cs.hash(&context.get_encoding()))?
            }
        };
        let cs = tree.cs;
        Ok(GroupAux {
            context,
            tree,
            tree_secret: TreeSecret::empty(cs),
            secrets,
            kp_secret,
            pending_updates: BTreeMap::new(),
            pending_commit: BTreeMap::new(),
        })
    }

    fn get_sender(&self) -> Sender {
        Sender {
            sender_type: SenderType::Member,
            sender: self.tree.my_pos.0 as u32,
        }
    }

    /// Generate and sign add proposal
    pub fn get_signed_add(
        &self,
        kp: &KeyPackage,
    ) -> Result<MLSPlaintext, ring::error::Unspecified> {
        let sender = self.get_sender();
        let add_content = MLSPlaintextCommon {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender,
            authenticated_data: vec![],
            content: ContentType::Proposal(Proposal::Add(Add {
                key_package: kp.clone(),
            })),
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
        keypackage: KeyPackage,
        secret: KeyPackageSecret,
    ) -> Result<MLSPlaintext, ring::error::Unspecified> {
        let sender = self.get_sender();
        let content = MLSPlaintextCommon {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender,
            authenticated_data: vec![],
            content: ContentType::Proposal(Proposal::Update(Update {
                key_package: keypackage,
            })),
        };
        let to_be_signed = MLSPlaintextTBS {
            context: self.context.clone(),
            content: content.clone(),
        }
        .get_encoding();
        let signature = self.kp_secret.credential_private_key.sign(&to_be_signed)?;
        let proposal = MLSPlaintext { content, signature };
        let proposal_id = ProposalId(self.tree.cs.hash(&proposal.get_encoding()));
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
        to_remove: LeafSize,
    ) -> Result<MLSPlaintext, ring::error::Unspecified> {
        let sender = self.get_sender();
        let add_content = MLSPlaintextCommon {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender,
            authenticated_data: vec![],
            content: ContentType::Proposal(Proposal::Remove(Remove {
                removed: to_remove.0,
            })),
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

    fn get_init_confirmed_transcript_hash(&self, sender: Sender, commit: &Commit) -> Vec<u8> {
        let interim_transcript_hash = b"".to_vec(); // TODO
        let content_to_commit = MLSPlaintextCommitContent::new(
            self.context.group_id.clone(),
            self.context.epoch,
            sender,
            commit.clone(),
        )
        .get_encoding();
        let to_hash = [interim_transcript_hash, content_to_commit].concat();
        self.tree.cs.hash(&to_hash)
    }

    fn get_interim_transcript_hash(
        &self,
        commit_confirmation: Vec<u8>,
        commit_msg_sig: Vec<u8>,
        confirmed_transcript: Vec<u8>,
    ) -> Vec<u8> {
        let commit_auth = MLSPlaintextCommitAuthData {
            confirmation: commit_confirmation,
            signature: commit_msg_sig,
        }
        .get_encoding();
        self.tree
            .cs
            .hash(&[confirmed_transcript, commit_auth].concat())
    }

    fn get_signed_commit(
        &self,
        plain: &MLSPlaintextCommon,
    ) -> Result<MLSPlaintext, ring::error::Unspecified> {
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

    fn get_welcome_msg(
        &self,
        updated_tree: &TreePublicKey,
        updated_group_context: &GroupContext,
        updated_secrets: &EpochSecrets<Sha256>,
        confirmation: Vec<u8>,
        interim_transcript_hash: Vec<u8>,
        positions: Vec<(NodeSize, KeyPackage)>,
    ) -> Result<Welcome, CommitError> {
        let group_info_p = GroupInfoPayload {
            group_id: updated_group_context.group_id.clone(),
            epoch: updated_group_context.epoch,
            tree: updated_tree.for_group_info(),
            confirmed_transcript_hash: updated_group_context.confirmed_transcript_hash.clone(),
            interim_transcript_hash,
            extensions: updated_group_context.extensions.clone(), // FIXME: gen new keypackage + extension with parent hash?
            confirmation,
            signer_index: self.get_sender().sender,
        };
        let signature = self
            .kp_secret
            .credential_private_key
            .sign(&group_info_p.get_encoding())?;
        let group_info = GroupInfo {
            payload: group_info_p,
            signature,
        };
        let (welcome_key, welcome_nonce) = updated_secrets.get_welcome_secret_key_nonce(
            self.tree.cs.aead_key_len(),
            self.tree.cs.aead_nonce_len(),
        )?;
        let encrypted_group_info =
            self.tree
                .cs
                .encrypt_group_info(&group_info, welcome_key, welcome_nonce)?;
        let mut secrets = Vec::with_capacity(positions.len());
        let epoch_secret = &updated_secrets.epoch_secret.0;
        for (_position, key_package) in positions.iter() {
            let group_secret = GroupSecret {
                epoch_secret: SecretVec::new(epoch_secret.expose_secret().to_vec()),
                path_secret: None, // FIXME
            };
            let encrypted_group_secret =
                self.tree.cs.seal_group_secret(group_secret, key_package)?; // FIXME: &self.context ?
            secrets.push(encrypted_group_secret);
        }
        Ok(Welcome {
            version: PROTOCOL_VERSION_MLS10,
            cipher_suite: self.tree.cs as u16,
            secrets,
            encrypted_group_info,
        })
    }

    /// Generate commit message for proposals.
    fn do_commit_proposals(
        &self,
        proposals: &[MLSPlaintext],
        init_genesis: bool,
    ) -> Result<(MLSPlaintext, Welcome, Option<HPKEPrivateKey>), CommitError> {
        // split proposals by types
        let mut add_proposals_ids: Vec<ProposalId> = Vec::new();
        let mut additions: Vec<Add> = Vec::new();
        let mut update_proposals_ids: Vec<ProposalId> = Vec::new();
        let mut updates: Vec<(LeafSize, Update, ProposalId)> = Vec::new();
        let mut remove_proposals_ids: Vec<ProposalId> = Vec::new();
        let mut removes: Vec<Remove> = Vec::new();
        for p in proposals.iter() {
            let proposal_id = ProposalId(self.tree.cs.hash(&p.get_encoding()));
            match &p.content.content {
                ContentType::Proposal(Proposal::Add(add)) => {
                    add_proposals_ids.push(proposal_id);
                    additions.push(add.clone());
                }
                ContentType::Proposal(Proposal::Update(update)) => {
                    update_proposals_ids.push(proposal_id.clone());
                    updates.push((
                        LeafSize(p.content.sender.sender),
                        update.clone(),
                        proposal_id,
                    ));
                }
                ContentType::Proposal(Proposal::Remove(remove)) => {
                    remove_proposals_ids.push(proposal_id);
                    removes.push(remove.clone());
                }
                _ => panic!("invalid proposal message type"),
            }
        }

        let mut updated_tree = self.tree.clone();
        let positions = updated_tree.update(&additions, &updates, &removes)?;

        let self_update_proposal = updates
            .iter()
            .find(|(sender, _, _)| *sender == self.tree.my_pos)
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
            init_genesis || proposals.is_empty() || !updates.is_empty() || !removes.is_empty();

        let (path, tree_secret, init_private_key) = if should_populate_path {
            // new init key
            let init_private_key = updated_tree.get_my_package_mut().update_init_key();

            // update path secrets
            let (path_nodes, parent_hash, tree_secret) =
                updated_tree.evolve(&self.context.get_encoding(), &init_private_key.marshal())?;

            let kp = updated_tree.get_my_package_mut();
            // update keypackage's parent_hash extension
            kp.payload.put_extension(&ext::ParentHashExt(parent_hash));
            kp.update_signature(credential_private_key)?;
            (
                Some(DirectPath {
                    leaf_key_package: kp.clone(),
                    nodes: path_nodes,
                }),
                tree_secret,
                Some(init_private_key),
            )
        } else {
            (None, TreeSecret::empty(self.tree.cs), None)
        };

        let commit = Commit {
            updates: update_proposals_ids,
            removes: remove_proposals_ids,
            adds: add_proposals_ids,
            path,
        };
        let updated_epoch = self.context.epoch + 1;
        let confirmed_transcript_hash =
            self.get_init_confirmed_transcript_hash(self.get_sender(), &commit);
        let updated_group_context = GroupContext {
            tree_hash: updated_tree.compute_tree_hash(),
            epoch: updated_epoch,
            confirmed_transcript_hash,
            ..self.context.clone()
        };
        let updated_group_context_hash = self.tree.cs.hash(&updated_group_context.get_encoding());
        let epoch_secrets = self
            .secrets
            .generate_new_epoch_secrets(&tree_secret.update_secret, updated_group_context_hash)?;
        let confirmation =
            epoch_secrets.compute_confirmation(&updated_group_context.confirmed_transcript_hash);
        let sender = self.get_sender();
        let commit_content = MLSPlaintextCommon {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender,
            authenticated_data: vec![],
            content: ContentType::Commit {
                commit,
                confirmation: confirmation.clone(),
            },
        };
        let signed_commit = self.get_signed_commit(&commit_content)?;
        let interim_transcript_hash = self.get_interim_transcript_hash(
            confirmation.clone(),
            signed_commit.signature.clone(),
            updated_group_context.confirmed_transcript_hash.clone(),
        );
        Ok((
            signed_commit,
            self.get_welcome_msg(
                &updated_tree,
                &updated_group_context,
                &epoch_secrets,
                confirmation,
                interim_transcript_hash,
                positions,
            )?,
            init_private_key,
        ))
    }

    /// commit proposals
    pub fn commit_proposals(
        &mut self,
        proposals: &[MLSPlaintext],
    ) -> Result<(MLSPlaintext, Welcome), CommitError> {
        let (msg, welcome, init_private_key) = self.do_commit_proposals(proposals, false)?;
        if let Some(init_private_key) = init_private_key {
            self.pending_commit.insert(
                ProposalId(self.tree.cs.hash(&msg.get_encoding())),
                init_private_key,
            );
        }
        Ok((msg, welcome))
    }

    /// commit the proposals in genesis
    ///
    /// panic if proposals are invalid
    pub fn init_commit(&mut self, proposals: &[MLSPlaintext]) -> (MLSPlaintext, Welcome) {
        let (msg, welcome, init_private_key) = self
            .do_commit_proposals(proposals, true)
            .expect("genesis proposals should be valid");
        if let Some(init_private_key) = init_private_key {
            self.pending_commit.insert(
                ProposalId(self.tree.cs.hash(&msg.get_encoding())),
                init_private_key,
            );
        }
        (msg, welcome)
    }

    fn verify_msg_signature(
        &self,
        msg: &MLSPlaintext,
        ra_verifier: &impl AttestedCertVerifier,
        now: Timespec,
    ) -> Result<(), CommitError> {
        let kp = self
            .tree
            .get_package(LeafSize(msg.content.sender.sender))
            .ok_or(CommitError::SenderNotFound)?;
        let pk = IdentityPublicKey::new_unsafe(kp.verify(ra_verifier, now)?.public_key.to_vec());
        Ok(msg.verify_signature(&self.context, &pk)?)
    }

    pub fn process_commit(
        &mut self,
        commit: MLSPlaintext,
        proposals: &[MLSPlaintext],
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
        let commit_content = CommitContent::new(self.tree.cs, &commit, proposals)
            .map_err(|_| CommitError::InvalidCommitMessage)?;

        // update credential_private_key for self updating proposal
        let self_update_proposal = commit_content
            .updates
            .iter()
            .find(|(sender, _, _)| *sender == self.tree.my_pos);
        let credential_private_key = if let Some((_, _, proposal_id)) = self_update_proposal {
            // apply the pending credential_private_key
            self.pending_updates
                .get(proposal_id)
                .ok_or(CommitError::PendingCredentialPrivateKeyNotFound)?
        } else {
            &self.kp_secret.credential_private_key
        };

        let commit_id = ProposalId(self.tree.cs.hash(&commit.get_encoding()));
        let init_private_key =
            if commit_content.commit.path.is_some() && commit_content.sender == self.tree.my_pos {
                // apply pending `init_private_key` if I'm the committer
                self.pending_commit
                    .get(&commit_id)
                    .ok_or(CommitError::PendingInitPrivateKeyNotFound)?
            } else {
                &self.kp_secret.init_private_key
            };

        // verify the leaf key package in commit path
        if let Some(path) = &commit_content.commit.path {
            if commit_content.sender == self.tree.my_pos {
                verify_keypackage_and_secrets(
                    &path.leaf_key_package,
                    init_private_key,
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
                &tree,
                &self.context.get_encoding(),
                &path.nodes,
                &init_private_key,
            )?;
            // Verify that the KeyPackage has a `parent_hash` extension and that its value
            // matches the new parent of the sender's leaf node.
            let ext = path
                .leaf_key_package
                .payload
                .find_extension::<ext::ParentHashExt>()?;
            if !bool::from(ext.0.ct_eq(&leaf_parent_hash)) {
                return Err(CommitError::LeafParentHashDontMatch);
            }

            tree.set_package(commit_content.sender, path.leaf_key_package.clone());
            Some(tree_diff)
        } else {
            None
        };

        // "Update the new GroupContext's confirmed and interim transcript hashes using the new Commit."
        let confirmed_transcript_hash = self.get_init_confirmed_transcript_hash(
            commit.content.sender.clone(),
            &commit_content.commit,
        );

        // FIXME: store interim transcript hash?
        let _interim_transcript_hash = self.get_interim_transcript_hash(
            commit_content.confirmation.clone(),
            commit.signature,
            confirmed_transcript_hash.clone(),
        );

        let updated_group_context = GroupContext {
            epoch: self.context.epoch + 1,
            tree_hash: tree.compute_tree_hash(),
            confirmed_transcript_hash,
            ..self.context.clone()
        };
        let updated_group_context_hash = tree.cs.hash(&updated_group_context.get_encoding());

        // "Use the commit_secret, the provisional GroupContext,
        // and the init secret from the previous epoch to compute the epoch secret and derived secrets for the new epoch."
        let epoch_secrets = self.secrets.generate_new_epoch_secrets(
            &self.tree_secret.update_secret,
            updated_group_context_hash,
        )?;
        let confirmation_computed =
            epoch_secrets.compute_confirmation(&updated_group_context.confirmed_transcript_hash);

        // "Use the confirmation_key for the new epoch to compute the confirmation MAC for this message,
        // as described below, and verify that it is the same as the confirmation field in the MLSPlaintext object."
        let confirmation =
            epoch_secrets.compute_confirmation(&updated_group_context.confirmed_transcript_hash);

        let confirmation_ok: bool = confirmation.ct_eq(&confirmation_computed).into();
        if !confirmation_ok {
            return Err(CommitError::GroupInfoIntegrityError);
        }

        // "If the above checks are successful, consider the updated GroupContext object as the current state of the group."
        self.context = updated_group_context;
        self.secrets = epoch_secrets;
        self.tree = tree;
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
        if commit_content.commit.path.is_some() && commit_content.sender == self.tree.my_pos {
            self.kp_secret.init_private_key = self
                .pending_commit
                .remove(&commit_id)
                .expect("impossible, checked above");
        }
        // clear pending commit secrets since they are invalid now
        self.pending_commit.clear();

        Ok(())
    }

    pub fn init_group(
        creator_kp: KeyPackage,
        secret: KeyPackageSecret,
        others: &[KeyPackage],
        ra_verifier: &impl AttestedCertVerifier,
        genesis_time: Timespec,
    ) -> Result<(Self, Vec<MLSPlaintext>, MLSPlaintext, Welcome), InitGroupError> {
        let mut kps = BTreeSet::new();
        for kp in others.iter() {
            if kps.contains(kp) {
                return Err(InitGroupError::DuplicateKeyPackage);
            } else {
                kp.verify(ra_verifier, genesis_time)?;
                kps.insert(kp.clone());
            }
        }
        if kps.contains(&creator_kp) {
            Err(InitGroupError::DuplicateKeyPackage)
        } else {
            creator_kp.verify(ra_verifier, genesis_time)?;
            let (context, tree) = GroupContext::init(creator_kp);
            let mut group = GroupAux::new(context, tree, secret)?;
            let add_proposals: Vec<MLSPlaintext> = others
                .iter()
                .map(|kp| group.get_signed_add(kp))
                .collect::<Result<_, _>>()?;
            let (commit, welcome) = group.init_commit(&add_proposals);
            Ok((group, add_proposals, commit, welcome))
        }
    }

    pub fn init_group_from_welcome(
        my_kp: KeyPackage,
        kp_secret: KeyPackageSecret,
        welcome: Welcome,
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
        let cs = match my_kp.payload.cipher_suite {
            x if x == (CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 as u16) => {
                Ok(CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256)
            }
            _ => Err(kp::Error::UnsupportedCipherSuite(
                my_kp.payload.cipher_suite,
            )),
        }?;
        let my_kp_hash = cs.hash(&my_kp.get_encoding());
        // * "Identify an entry in the secrets array..."
        let msecret = welcome
            .secrets
            .iter()
            .find(|s| s.key_package_hash == my_kp_hash);
        let secret = msecret.ok_or(ProcessWelcomeError::KeyPackageNotFound)?;
        // * "Decrypt the encrypted_group_secrets using HPKE..."
        let group_secret = cs
            .open_group_secret(&secret, &kp_secret)?
            .ok_or(ProcessWelcomeError::InvalidGroupSecret)?;
        let epoch_secret =
            EpochSecrets::<Sha256>::get_epoch_secret(&group_secret.epoch_secret.expose_secret())?;
        // * "From the epoch_secret in the decrypted GroupSecrets object, derive the welcome_secret, welcome_key, and welcome_nonce..."
        let (welcome_key, welcome_nonce) = EpochSecrets::derive_welcome_secrets(
            &epoch_secret,
            cs.aead_key_len(),
            cs.aead_nonce_len(),
        )?;
        let group_info = cs
            .open_group_info(&welcome.encrypted_group_info, welcome_key, welcome_nonce)?
            .ok_or(ProcessWelcomeError::InvalidGroupInfo)?;

        // convert Vec<Option<Node>> to Vec<Node>
        let nodes = group_info
            .payload
            .tree
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, node)| {
                node.unwrap_or_else(|| {
                    if i % 2 == 0 {
                        Node::Leaf(None)
                    } else {
                        Node::Parent(None)
                    }
                })
            })
            .collect::<Vec<_>>();

        // * "Verify the signature on the GroupInfo object..."
        let signer = match nodes.get(group_info.payload.signer_index as usize) {
            Some(Node::Leaf(Some(kp))) => Ok(kp.clone()),
            _ => Err(ProcessWelcomeError::KeyPackageNotFound),
        }?;
        let identity_pk = IdentityPublicKey::new_unsafe(
            signer
                .verify(ra_verifier, genesis_time)?
                .public_key
                .to_vec(),
        );
        let payload = group_info.payload.get_encoding();
        identity_pk
            .verify_signature(&payload, &group_info.signature)
            .map_err(kp::Error::SignatureVerifyError)?;
        // * "Identify a leaf in the tree array..."
        let node_index = nodes
            .iter()
            .enumerate()
            .find(|(_, node)| match node {
                Node::Leaf(Some(kp)) => kp == &my_kp,
                _ => false,
            })
            .map(|(i, _)| i)
            .ok_or(ProcessWelcomeError::KeyPackageNotFound)?;
        // * "Verify the integrity of the ratchet tree..."
        // * "Construct a new group state using the information in the GroupInfo object..."
        let tree =
            TreePublicKey::from_group_info(node_index, nodes, ra_verifier, genesis_time, cs)?;
        if let Some(_path_secret) = group_secret.path_secret {
            // FIXME
        }
        // * "Set the confirmed transcript hash in the new state to the value of the confirmed_transcript_hash in the GroupInfo."
        let context = GroupContext {
            group_id: group_info.payload.group_id.clone(),
            epoch: group_info.payload.epoch,
            tree_hash: tree.compute_tree_hash(),
            confirmed_transcript_hash: group_info.payload.confirmed_transcript_hash.clone(),
            extensions: group_info.payload.extensions,
        };

        // * "Use the epoch_secret from the GroupSecrets object to generate the epoch secret and other derived secrets for the current epoch."
        let secrets = EpochSecrets::from_epoch_secret(
            (group_secret.epoch_secret, epoch_secret),
            tree.cs.hash(&context.get_encoding()),
        )?;
        let group = GroupAux {
            context,
            tree,
            tree_secret: TreeSecret::empty(cs),
            kp_secret,
            secrets,
            pending_updates: BTreeMap::new(),
            pending_commit: BTreeMap::new(),
        };
        // * "Verify the confirmation MAC in the GroupInfo using the derived confirmation key and the confirmed_transcript_hash from the GroupInfo."
        let confirmation = group
            .secrets
            .compute_confirmation(&group.context.confirmed_transcript_hash);

        let confirmation_ok: bool = confirmation.ct_eq(&group_info.payload.confirmation).into();
        if !confirmation_ok {
            return Err(ProcessWelcomeError::GroupInfoIntegrityError);
        }
        Ok(group)
    }
}

const TDBE_GROUP_ID: &[u8] = b"Crypto.com Chain Council Node Transaction Data Bootstrap Enclave";

/// spec: draft-ietf-mls-protocol.md#group-state
#[derive(Clone, Debug, Eq, PartialEq)]
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
    /// 0..2^16-1
    pub extensions: Vec<ext::ExtensionEntry>,
}

impl Codec for GroupContext {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_vec_u8_u8(bytes, &self.group_id);
        self.epoch.encode(bytes);
        encode_vec_u8_u8(bytes, &self.tree_hash);
        encode_vec_u8_u8(bytes, &self.confirmed_transcript_hash);
        codec::encode_vec_u16(bytes, &self.extensions);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let group_id = read_vec_u8_u8(r)?;
        let epoch = u64::read(r)?;
        let tree_hash = read_vec_u8_u8(r)?;
        let confirmed_transcript_hash = read_vec_u8_u8(r)?;
        let extensions = codec::read_vec_u16(r)?;
        Some(Self {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            extensions,
        })
    }
}

impl GroupContext {
    pub fn init(creator_kp: KeyPackage) -> (Self, TreePublicKey) {
        let extensions = creator_kp.payload.extensions.clone();
        let tree = TreePublicKey::init(creator_kp);
        (
            GroupContext {
                group_id: TDBE_GROUP_ID.to_vec(),
                epoch: 0,
                tree_hash: tree.compute_tree_hash(),
                confirmed_transcript_hash: vec![],
                extensions,
            },
            tree,
        )
    }
}

/// spec: draft-ietf-mls-protocol.md#Welcoming-New-Members
#[derive(Debug, Clone)]
pub struct GroupInfoPayload {
    /// 0..255 bytes -- application-defined id
    pub group_id: Vec<u8>,
    /// version of the group key
    /// (incremented by 1 for each Commit message
    /// that is processed)
    pub epoch: u64,
    /// 1..2^32-1
    /// FIXME representation may change https://github.com/mlswg/mls-protocol/issues/344
    pub tree: Vec<Option<Node>>,
    /// 0..255
    pub confirmed_transcript_hash: Vec<u8>,
    /// 0..255
    pub interim_transcript_hash: Vec<u8>,
    /// 0..2^16-1
    pub extensions: Vec<ext::ExtensionEntry>,
    /// 0..255
    pub confirmation: Vec<u8>,
    pub signer_index: u32,
}

impl Codec for GroupInfoPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_vec_u8_u8(bytes, &self.group_id);
        self.epoch.encode(bytes);
        encode_vec_option_u32(bytes, &self.tree);
        encode_vec_u8_u8(bytes, &self.confirmed_transcript_hash);
        encode_vec_u8_u8(bytes, &self.interim_transcript_hash);
        codec::encode_vec_u16(bytes, &self.extensions);
        encode_vec_u8_u8(bytes, &self.confirmation);
        self.signer_index.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let group_id = read_vec_u8_u8(r)?;
        let epoch = u64::read(r)?;
        let tree = read_vec_option_u32(r)?;
        let confirmed_transcript_hash = read_vec_u8_u8(r)?;
        let interim_transcript_hash = read_vec_u8_u8(r)?;
        let extensions = codec::read_vec_u16(r)?;
        let confirmation = read_vec_u8_u8(r)?;
        let signer_index = u32::read(r)?;
        Some(GroupInfoPayload {
            group_id,
            epoch,
            tree,
            confirmed_transcript_hash,
            interim_transcript_hash,
            extensions,
            confirmation,
            signer_index,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#Welcoming-New-Members
#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub payload: GroupInfoPayload,
    // 0..2^16-1
    pub signature: Vec<u8>,
}

impl Codec for GroupInfo {
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

#[derive(thiserror::Error, Debug)]
pub enum CommitError {
    #[error("keypackage verify failed: {0}")]
    KeyPackageVerifyFail(#[from] kp::Error),
    #[error("find extension failed: {0}")]
    FindExtensionFail(#[from] kp::FindExtensionError),
    #[error("Epoch does not match")]
    GroupEpochError,
    #[error("group info integrity check failed")]
    GroupInfoIntegrityError,
    #[error("ratchet tree integrity check failed: {0}")]
    TreeVerifyFail(#[from] TreeIntegrityError),
    #[error("decrypted path secret don't match the public key")]
    PathSecretPublicKeyDontMatch,
    #[error("parent hash extension in leaf keypackage don't match")]
    LeafParentHashDontMatch,
    #[error("message sender keypackage not found")]
    SenderNotFound,
    #[error("sign/verify signature error: {0}")]
    SignatureCryptographicError(#[from] ring::error::Unspecified),
    #[error("commit path is not populated")]
    CommitPathNotPopulated,
    #[error("hkdf error: {0}")]
    HkdfError(#[from] hkdf::InvalidLength),
    #[error("hpke error: {0}")]
    HpkeError(#[from] hpke::HpkeError),
    #[error("pending init_private_key not found")]
    PendingInitPrivateKeyNotFound,
    #[error("pending credential private key not found")]
    PendingCredentialPrivateKeyNotFound,
    #[error("Node size exceeds u32 when process add proposal")]
    TooManyNodes,
    #[error("Commit message is invalid")]
    InvalidCommitMessage,
    #[error("fail to encrypt group info: {0}")]
    EncryptGroupInfoError(#[from] aead::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum ProcessWelcomeError {
    #[error("hpke error: {0}")]
    HpkeError(#[from] hpke::HpkeError),
    #[error("keypackage verify failed: {0}")]
    KeyPackageVerifyFail(#[from] kp::Error),
    #[error("ratchet tree integrity check failed: {0}")]
    TreeVerifyFail(#[from] TreeIntegrityError),
    #[error("key package not found")]
    KeyPackageNotFound,
    #[error("cipher suite in welcome don't match keypackage")]
    CipherSuiteDontMatch,
    #[error("version in welcome don't match keypackage")]
    VersionDontMatch,
    #[error("group info integrity check failed")]
    GroupInfoIntegrityError,
    #[error("fail to decode group secret")]
    InvalidGroupSecret,
    #[error("fail to decode group info")]
    InvalidGroupInfo,
    #[error("invalid epoch secret length: {0}")]
    InvalidEpochSecretLength(#[from] hkdf::InvalidPrkLength),
    #[error("hpdf error: {0}")]
    HkdfError(#[from] hkdf::InvalidLength),
    #[error("fail to decrypt group info: {0}")]
    DecryptGroupInfoError(#[from] aead::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum InitGroupError {
    #[error("keypackage verify failed: {0}")]
    KeyPackageVerifyFail(#[from] kp::Error),
    #[error("duplicate keypackages")]
    DuplicateKeyPackage,
    #[error("sign/verify signature error: {0}")]
    SignatureCryptographicError(#[from] ring::error::Unspecified),
    #[error("invalid secret length: {0}")]
    InvalidSecretLength(#[from] hkdf::InvalidLength),
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::credential::Credential;
    use crate::extensions::{self as ext, MLSExtension};
    use crate::key::{HPKEPrivateKey, IdentityPrivateKey};
    use crate::keypackage::{
        KeyPackage, KeyPackagePayload, MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
        PROTOCOL_VERSION_MLS10,
    };
    use crate::tree_math::ParentSize;
    use chrono::{DateTime, Utc};
    use ra_client::{
        AttestedCertVerifier, CertVerifyResult, EnclaveCertVerifierError, ENCLAVE_CERT_VERIFIER,
    };
    use rustls::internal::msgs::codec::Codec;

    #[derive(Clone)]
    struct MockVerifier();

    impl AttestedCertVerifier for MockVerifier {
        fn verify_attested_cert(
            &self,
            certificate: &[u8],
            _now: DateTime<Utc>,
        ) -> Result<CertVerifyResult, EnclaveCertVerifierError> {
            static VECTOR: &[u8] = include_bytes!("../tests/test_vectors/keypackage.bin");
            let kp = <KeyPackage>::read_bytes(VECTOR).expect("decode");
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

    fn get_fake_keypackage() -> (KeyPackage, KeyPackageSecret) {
        let keypair = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        let extensions = vec![
            ext::SupportedVersionsExt(vec![PROTOCOL_VERSION_MLS10]).entry(),
            ext::SupportedCipherSuitesExt(vec![MLS10_128_DHKEMP256_AES128GCM_SHA256_P256]).entry(),
            ext::LifeTimeExt::new(0, 100).entry(),
        ];

        let private_key =
            IdentityPrivateKey::from_pkcs8(keypair.as_ref()).expect("invalid private key");
        let (hpke_secret, hpke_public) = HPKEPrivateKey::generate();

        let payload = KeyPackagePayload {
            version: PROTOCOL_VERSION_MLS10,
            cipher_suite: MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
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
                init_private_key: hpke_secret,
            },
        )
    }

    #[test]
    fn test_sign_verify_add() {
        let (creator_kp, creator_secret) = get_fake_keypackage();
        let (to_be_added, _) = get_fake_keypackage();
        let (context, tree) = GroupContext::init(creator_kp);
        let group_aux = GroupAux::new(context, tree, creator_secret).unwrap();
        let plain = group_aux.get_signed_add(&to_be_added).unwrap();
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
        let (mut creator_group, adds, commit, welcome) = GroupAux::init_group(
            creator_kp,
            creator_secret,
            &[to_be_added.clone()],
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
        creator_group
            .process_commit(commit, &adds, &MockVerifier {}, 0)
            .expect("commit ok");
        // they should get to the same context
        assert_eq!(&added_group.context, &creator_group.context);
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
                ProposalId(vec![]),
            )],
            &[],
        )
        .unwrap();
        assert_eq!(tree.nodes.len(), 3);
        tree.update(&[], &[], &[Remove { removed: 1 }]).unwrap();
        assert_eq!(tree.nodes.len(), 3);
        assert!(tree.nodes[2].is_empty_node());
        tree.update(
            &[Add {
                key_package: to_be_added,
            }],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(tree.nodes.len(), 3);
        assert!(!tree.nodes[2].is_empty_node());
    }

    #[test]
    fn test_group_update() {
        let (member1, member1_secret) = get_fake_keypackage();
        let (member2, member2_secret) = get_fake_keypackage();
        let (member3, member3_secret) = get_fake_keypackage();
        let ra_verifier = MockVerifier {};

        // add member2 in genesis
        let (mut member1_group, proposals, commit, welcome) =
            GroupAux::init_group(member1, member1_secret, &[member2.clone()], &ra_verifier, 0)
                .expect("group init");

        // after commit/welcome get confirmed
        member1_group
            .process_commit(commit, &proposals, &ra_verifier, 0)
            .expect("commit ok");
        let mut member2_group =
            GroupAux::init_group_from_welcome(member2, member2_secret, welcome, &ra_verifier, 0)
                .expect("group init from welcome");

        // they should get to the same context
        assert_eq!(&member1_group.context, &member2_group.context);

        // add member3
        let proposals = vec![member1_group.get_signed_add(&member3).unwrap()];
        let (commit, welcome) = member1_group.commit_proposals(&proposals).unwrap();

        // after commit/welcome get confirmed
        member1_group
            .process_commit(commit.clone(), &proposals, &ra_verifier, 0)
            .expect("commit ok");
        member2_group
            .process_commit(commit, &proposals, &ra_verifier, 0)
            .expect("commit ok");
        let mut member3_group =
            GroupAux::init_group_from_welcome(member3, member3_secret, welcome, &ra_verifier, 0)
                .expect("group init from welcome");

        // they should get to the same context
        assert_eq!(&member1_group.context, &member2_group.context);
        assert_eq!(&member2_group.context, &member3_group.context);

        // check add result
        assert_eq!(member3_group.tree.my_pos, LeafSize(2));
        member2_group
            .tree
            .get_package(member3_group.tree.my_pos)
            .expect("member3 should exists");

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
                .get_package(member2_group.tree.my_pos)
                .unwrap()
                .payload
                .credential,
            &member2.payload.credential
        );

        // remove member3
        let proposals = vec![member1_group
            .get_signed_remove(member3_group.tree.my_pos)
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
        assert_eq!(
            member2_group.tree.get_package(member3_group.tree.my_pos),
            None
        );
    }

    #[test]
    fn test_invalid_commit() {
        // process invalid commit don't end up partial mutated state.
        let (member1, member1_secret) = get_fake_keypackage();
        let (member2, member2_secret) = get_fake_keypackage();
        let (member3, _member3_secret) = get_fake_keypackage();
        let ra_verifier = MockVerifier {};

        // add member2 in genesis
        let (mut member1_group, proposals, commit, welcome) =
            GroupAux::init_group(member1, member1_secret, &[member2.clone()], &ra_verifier, 0)
                .expect("group init");

        // after commit/welcome get confirmed
        member1_group
            .process_commit(commit, &proposals, &ra_verifier, 0)
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

        let old_parent_node = member2_group
            .tree
            .get_parent_node(ParentSize(0))
            .unwrap()
            .clone();
        // decryption error
        assert!(matches!(
            member2_group.process_commit(commit, &[], &ra_verifier, 0),
            Err(CommitError::HpkeError(hpke::HpkeError::InvalidTag))
        ));
        assert_eq!(
            old_parent_node.get_encoding(),
            member2_group
                .tree
                .get_parent_node(ParentSize(0))
                .unwrap()
                .get_encoding()
        );
    }
}
