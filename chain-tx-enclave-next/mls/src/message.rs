use std::collections::BTreeMap;
use std::fmt::Debug;

use generic_array::GenericArray;
use hpke::Serializable;
use secrecy::{ExposeSecret, Secret};

use crate::ciphersuite::{
    CipherSuite, CipherSuiteTag, HashValue, KeySecret, NodeSecret, PublicKey,
};
use crate::extensions::ExtensionEntry;
use crate::key::{HPKEPublicKey, IdentityPublicKey};
use crate::keypackage::{KeyPackage, ProtocolVersion};
use crate::tree_math::LeafSize;
use crate::utils::{
    decode_option, encode_option, encode_vec_u32, encode_vec_u8_u16, encode_vec_u8_u8,
    read_arr_u8_u16, read_vec_u32, read_vec_u8_u16, read_vec_u8_u8,
};
use crate::{codec, Codec, Reader};

/// spec: draft-ietf-mls-protocol.md#Add
#[derive(Debug, Clone)]
pub struct Add<CS: CipherSuite> {
    pub key_package: KeyPackage<CS>,
}

/// spec: draft-ietf-mls-protocol.md#Update
#[derive(Debug, Clone)]
pub struct Update<CS: CipherSuite> {
    pub key_package: KeyPackage<CS>,
}

/// spec: draft-ietf-mls-protocol.md#Remove
#[derive(Debug, Clone)]
pub struct Remove {
    pub removed: LeafSize,
}

/// spec: draft-ietf-mls-protocol.md#Proposal
/// #[repr(u8)]
#[derive(Debug, Clone)]
pub enum Proposal<CS: CipherSuite> {
    // Invalid = 0,
    Add(Add<CS>),       // = 1,
    Update(Update<CS>), // = 2,
    Remove(Remove),     // = 3,
}

impl<CS: CipherSuite> Codec for Proposal<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Proposal::Add(Add { key_package }) => {
                1u8.encode(bytes);
                key_package.encode(bytes);
            }
            Proposal::Update(Update { key_package }) => {
                2u8.encode(bytes);
                key_package.encode(bytes);
            }
            Proposal::Remove(Remove { removed }) => {
                3u8.encode(bytes);
                removed.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let tag = u8::read(r)?;
        match tag {
            1 => {
                let key_package = KeyPackage::read(r)?;
                Some(Proposal::Add(Add { key_package }))
            }
            2 => {
                let key_package = KeyPackage::read(r)?;
                Some(Proposal::Update(Update { key_package }))
            }
            3 => {
                let removed = LeafSize::read(r)?;
                Some(Proposal::Remove(Remove { removed }))
            }
            _ => None,
        }
    }
}

/// spec: draft-ietf-mls-protocol.md#Message-Framing
/// + draft-ietf-mls-protocol.md#MContent-Signing-and-Encryption
#[derive(Debug, Clone)]
pub struct MLSPlaintextCommon<CS: CipherSuite> {
    /// 0..255 bytes -- application-defined id
    pub group_id: Vec<u8>,
    /// version of the group key
    /// (incremented by 1 for each Commit message
    /// that is processed)
    pub epoch: u64,
    pub sender: Sender,
    /// 0..2^32-1
    pub authenticated_data: Vec<u8>,
    pub content: ContentType<CS>,
}

impl<CS: CipherSuite> Codec for MLSPlaintextCommon<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_vec_u8_u8(bytes, &self.group_id);
        self.epoch.encode(bytes);
        self.sender.encode(bytes);
        encode_vec_u32(bytes, &self.authenticated_data);
        match &self.content {
            ContentType::Application { application_data } => {
                1u8.encode(bytes);
                encode_vec_u32(bytes, &application_data);
            }
            ContentType::Proposal(p) => {
                2u8.encode(bytes);
                p.encode(bytes);
            }
            ContentType::Commit {
                commit,
                confirmation,
            } => {
                3u8.encode(bytes);
                commit.encode(bytes);
                confirmation.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let group_id = read_vec_u8_u8(r)?;
        let epoch = u64::read(r)?;
        let sender = Sender::read(r)?;
        let authenticated_data: Vec<u8> = read_vec_u32(r)?;
        let tag = u8::read(r)?;
        let content = match tag {
            1 => {
                let application_data: Vec<u8> = read_vec_u32(r)?;
                Some(ContentType::Application { application_data })
            }
            2 => {
                let proposal = Proposal::read(r)?;
                Some(ContentType::Proposal(proposal))
            }
            3 => {
                let commit = Commit::read(r)?;
                let confirmation = HashValue::read(r)?;
                Some(ContentType::Commit {
                    commit,
                    confirmation,
                })
            }
            _ => None,
        }?;
        Some(MLSPlaintextCommon {
            group_id,
            epoch,
            sender,
            authenticated_data,
            content,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#Message-Framing\
#[derive(Debug, Clone)]
pub struct MLSPlaintext<CS: CipherSuite> {
    pub content: MLSPlaintextCommon<CS>,
    /// 0..2^16-1
    pub signature: Vec<u8>,
}

impl<CS: CipherSuite> Codec for MLSPlaintext<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.content.encode(bytes);
        encode_vec_u8_u16(bytes, &self.signature);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let content = MLSPlaintextCommon::read(r)?;
        let signature = read_vec_u8_u16(r)?;
        Some(MLSPlaintext { content, signature })
    }
}

impl<CS: CipherSuite> MLSPlaintext<CS> {
    pub fn verify_signature(
        &self,
        context: &GroupContext<CS>,
        public_key: &IdentityPublicKey,
    ) -> Result<(), ring::error::Unspecified> {
        let payload = MLSPlaintextTBS {
            context: context.clone(),
            content: self.content.clone(),
        }
        .get_encoding();
        public_key.verify_signature(&payload, &self.signature)
    }
}

/// spec: draft-ietf-mls-protocol.md#group-state
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupContext<CS: CipherSuite> {
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
    pub tree_hash: HashValue<CS>,
    /// field contains a running hash over
    /// the messages that led to this state.
    /// 0..255
    pub confirmed_transcript_hash: HashValue<CS>,
    /// 0..2^16-1
    pub extensions: Vec<ExtensionEntry>,
}

impl<CS: CipherSuite> Codec for GroupContext<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_vec_u8_u8(bytes, &self.group_id);
        self.epoch.encode(bytes);
        self.tree_hash.encode(bytes);
        self.confirmed_transcript_hash.encode(bytes);
        codec::encode_vec_u16(bytes, &self.extensions);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let group_id = read_vec_u8_u8(r)?;
        let epoch = u64::read(r)?;
        let tree_hash = HashValue::read(r)?;
        let confirmed_transcript_hash = HashValue::read(r)?;
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

/// payload to be signed
/// spec: draft-ietf-mls-protocol.md#Content-Signing-and-Encryption
#[derive(Debug)]
pub struct MLSPlaintextTBS<CS: CipherSuite> {
    /// TODO: https://github.com/mlswg/mls-protocol/issues/323 may be removed?
    pub context: GroupContext<CS>,
    pub content: MLSPlaintextCommon<CS>,
}

impl<CS: CipherSuite> Codec for MLSPlaintextTBS<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.content.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let context = GroupContext::read(r)?;
        let content = MLSPlaintextCommon::read(r)?;
        Some(MLSPlaintextTBS { context, content })
    }
}

impl<CS: CipherSuite> MLSPlaintext<CS> {
    pub fn get_commit(&self) -> Option<&Commit<CS>> {
        match &self.content.content {
            ContentType::Commit { commit, .. } => Some(commit),
            _ => None,
        }
    }
    pub fn get_add(&self) -> Option<&Add<CS>> {
        match &self.content.content {
            ContentType::Proposal(Proposal::Add(add)) => Some(add),
            _ => None,
        }
    }
    pub fn get_update(&self) -> Option<&Update<CS>> {
        match &self.content.content {
            ContentType::Proposal(Proposal::Update(update)) => Some(update),
            _ => None,
        }
    }
    pub fn get_remove(&self) -> Option<&Remove> {
        match &self.content.content {
            ContentType::Proposal(Proposal::Remove(remove)) => Some(remove),
            _ => None,
        }
    }
}

/// 0..255 -- hash of the MLSPlaintext in which the Proposal was sent
/// spec: draft-ietf-mls-protocol.md#Commit
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct ProposalId<CS: CipherSuite>(pub HashValue<CS>);

impl<CS: CipherSuite> Codec for ProposalId<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        HashValue::read(r).map(Self)
    }
}

/// spec: draft-ietf-mls-protocol.md#Commit
#[derive(Debug, Clone)]
pub struct Commit<CS: CipherSuite> {
    /// 0..2^16-1
    pub updates: Vec<ProposalId<CS>>,
    /// 0..2^16-1
    pub removes: Vec<ProposalId<CS>>,
    /// 0..2^16-1
    pub adds: Vec<ProposalId<CS>>,
    /// "path field of a Commit message MUST be populated if the Commit covers at least one Update or Remove proposal"
    /// "path field MUST also be populated if the Commit covers no proposals at all (i.e., if all three proposal vectors are empty)."
    pub path: Option<DirectPath<CS>>,
}

impl<CS: CipherSuite> Codec for Commit<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u16(bytes, &self.updates);
        codec::encode_vec_u16(bytes, &self.removes);
        codec::encode_vec_u16(bytes, &self.adds);
        encode_option(bytes, &self.path);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let updates: Vec<ProposalId<_>> = codec::read_vec_u16(r)?;
        let removes: Vec<ProposalId<_>> = codec::read_vec_u16(r)?;
        let adds: Vec<ProposalId<_>> = codec::read_vec_u16(r)?;
        let path: Option<DirectPath<_>> = decode_option(r)?;

        Some(Commit {
            updates,
            removes,
            adds,
            path,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#Group-State
#[derive(Debug, Clone)]
pub struct MLSPlaintextCommitContent<CS: CipherSuite> {
    /// 0..255 bytes -- application-defined id
    pub group_id: Vec<u8>,
    /// version of the group key
    /// (incremented by 1 for each Commit message
    /// that is processed)
    pub epoch: u64,
    pub sender: Sender,
    /// always Commit = 3
    content_type: u8,
    pub commit: Commit<CS>,
}

impl<CS: CipherSuite> MLSPlaintextCommitContent<CS> {
    pub fn new(group_id: Vec<u8>, epoch: u64, sender: Sender, commit: Commit<CS>) -> Self {
        Self {
            group_id,
            epoch,
            sender,
            content_type: 3,
            commit,
        }
    }
}

impl<CS: CipherSuite> Codec for MLSPlaintextCommitContent<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_vec_u8_u8(bytes, &self.group_id);
        self.epoch.encode(bytes);
        self.sender.encode(bytes);
        self.content_type.encode(bytes);
        self.commit.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let group_id = read_vec_u8_u8(r)?;
        let epoch = u64::read(r)?;
        let sender = Sender::read(r)?;
        let content_type = u8::read(r)?;
        let commit = Commit::read(r)?;

        Some(Self {
            group_id,
            epoch,
            sender,
            content_type,
            commit,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#Group-State
#[derive(Debug, Clone)]
pub struct MLSPlaintextCommitAuthData<CS: CipherSuite> {
    /// 0..255
    pub confirmation: HashValue<CS>,
    /// 0..2^16-1
    pub signature: Vec<u8>,
}

impl<CS: CipherSuite> Codec for MLSPlaintextCommitAuthData<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.confirmation.encode(bytes);
        encode_vec_u8_u16(bytes, &self.signature);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let confirmation = HashValue::read(r)?;
        let signature = read_vec_u8_u16(r)?;
        Some(Self {
            confirmation,
            signature,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#Welcoming-New-Members
pub struct Welcome<CS: CipherSuite> {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuiteTag,
    /// 0..2^32-1
    pub secrets: Vec<EncryptedGroupSecrets<CS>>,
    /// 0..2^32-1
    pub encrypted_group_info: Vec<u8>,
}

/// spec: draft-ietf-mls-protocol.md#Welcoming-New-Members
pub struct PathSecret<CS: CipherSuite> {
    /// 1..255
    pub path_secret: Secret<NodeSecret<CS>>,
}

// not printing out the secret values
impl<CS: CipherSuite> Debug for PathSecret<CS> {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        Ok(())
    }
}

impl<CS: CipherSuite> Codec for PathSecret<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.path_secret.expose_secret().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        Some(PathSecret {
            path_secret: Secret::new(NodeSecret::<CS>::read(r)?),
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#Welcoming-New-Members
pub struct GroupSecret<CS: CipherSuite> {
    /// 1..255
    pub joiner_secret: Secret<KeySecret<CS>>,
    pub path_secret: Option<PathSecret<CS>>,
}

// not printing out the secret values
impl<CS: CipherSuite> Debug for GroupSecret<CS> {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        Ok(())
    }
}

impl<CS: CipherSuite> Codec for GroupSecret<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.joiner_secret.expose_secret().encode(bytes);
        encode_option(bytes, &self.path_secret);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let joiner_secret = Secret::new(KeySecret::<CS>::read(r)?);
        let path_secret = decode_option(r)?;

        Some(GroupSecret {
            joiner_secret,
            path_secret,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#Welcoming-New-Members
pub struct EncryptedGroupSecrets<CS: CipherSuite> {
    pub encrypted_group_secrets: HPKECiphertext<CS>,
    pub key_package_hash: HashValue<CS>,
}

/// spec: draft-ietf-mls-protocol.md#Direct-Paths
#[derive(Debug, Clone)]
pub struct HPKECiphertext<CS: CipherSuite> {
    /// 0..2^16-1
    pub kem_output: GenericArray<u8, <PublicKey<CS> as Serializable>::OutputSize>,
    /// 0..2^16-1
    pub ciphertext: Vec<u8>,
}

impl<CS: CipherSuite> Codec for HPKECiphertext<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_vec_u8_u16(bytes, &self.kem_output);
        encode_vec_u8_u16(bytes, &self.ciphertext);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let kem_output = read_arr_u8_u16(r)?;
        let ciphertext = read_vec_u8_u16(r)?;

        Some(HPKECiphertext {
            kem_output,
            ciphertext,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#Direct-Paths
#[derive(Debug, Clone)]
pub struct DirectPathNode<CS: CipherSuite> {
    pub public_key: HPKEPublicKey<CS>,
    /// 0..2^32-1
    pub encrypted_path_secret: Vec<HPKECiphertext<CS>>,
}

impl<CS: CipherSuite> Codec for DirectPathNode<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public_key.encode(bytes);
        encode_vec_u32(bytes, &self.encrypted_path_secret);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let public_key = HPKEPublicKey::read(r)?;
        let encrypted_path_secret: Vec<HPKECiphertext<_>> = read_vec_u32(r)?;

        Some(DirectPathNode {
            public_key,
            encrypted_path_secret,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#Direct-Paths
#[derive(Debug, Clone)]
pub struct DirectPath<CS: CipherSuite> {
    pub leaf_key_package: KeyPackage<CS>,
    /// 0..2^16-1
    pub nodes: Vec<DirectPathNode<CS>>,
}

impl<CS: CipherSuite> Codec for DirectPath<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.leaf_key_package.encode(bytes);
        codec::encode_vec_u16(bytes, &self.nodes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let leaf_key_package = KeyPackage::read(r)?;
        let nodes: Vec<DirectPathNode<_>> = codec::read_vec_u16(r)?;

        Some(DirectPath {
            leaf_key_package,
            nodes,
        })
    }
}

/// spec: draft-ietf-mls-protocol.md#Message-Framing
/// #[repr(u8)]
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum ContentType<CS: CipherSuite> {
    Application {
        // <0..2^32-1>
        application_data: Vec<u8>,
    }, //= 1,
    Proposal(Proposal<CS>), //= 2,
    Commit {
        commit: Commit<CS>,
        // 0..255
        confirmation: HashValue<CS>,
    }, //= 3,
}

/// spec: draft-ietf-mls-protocol.md#Message-Framing
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum SenderType {
    Member = 1,
    Preconfigured = 2,
    NewMember = 3,
}

/// spec: draft-ietf-mls-protocol.md#Message-Framing
#[derive(Debug, Clone)]
pub struct Sender {
    pub sender_type: SenderType,
    pub sender: LeafSize,
}

impl Codec for Sender {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.sender_type as u8).encode(bytes);
        self.sender.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let sender_t = u8::read(r)?;
        let sender_type = match sender_t {
            1 => Some(SenderType::Member),
            2 => Some(SenderType::Preconfigured),
            3 => Some(SenderType::NewMember),
            _ => None,
        }?;
        let sender = LeafSize::read(r)?;
        Some(Self {
            sender_type,
            sender,
        })
    }
}

/// Content of commit message and proposals
pub struct CommitContent<CS: CipherSuite> {
    pub sender: LeafSize,
    pub commit: Commit<CS>,
    pub confirmation: HashValue<CS>,
    pub additions: Vec<Add<CS>>,
    pub updates: Vec<(LeafSize, Update<CS>, ProposalId<CS>)>,
    pub removes: Vec<Remove>,
}

impl<CS: CipherSuite + Ord> CommitContent<CS> {
    /// Verify and extract message contents
    pub fn new(commit: &MLSPlaintext<CS>, proposals: &[MLSPlaintext<CS>]) -> Result<Self, ()> {
        let sender = commit.content.sender.sender;
        let (commit, confirmation) = match &commit.content.content {
            ContentType::Commit {
                commit,
                confirmation,
            } => (commit.clone(), confirmation.clone()),
            _ => {
                return Err(());
            }
        };

        // "Verify that the path value is populated if either of the updates or removes vectors has length greater than zero
        // all of the updates, removes, and adds vectors are empty."
        let has_update_or_remove = !commit.updates.is_empty() || !commit.removes.is_empty();
        let dont_has_proposal =
            commit.adds.is_empty() && commit.updates.is_empty() && commit.removes.is_empty();
        if (has_update_or_remove || dont_has_proposal) && commit.path.is_none() {
            return Err(());
        }

        let proposals_ids = proposals
            .iter()
            .map(|p| (ProposalId(CS::hash(&p.get_encoding())), p))
            .collect::<BTreeMap<_, _>>();

        let additions = commit
            .adds
            .iter()
            .map(|proposal_id| {
                proposals_ids
                    .get(proposal_id)
                    .and_then(|add| add.get_add().cloned())
                    .ok_or(())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let updates = commit
            .updates
            .iter()
            .map(|proposal_id| {
                proposals_ids
                    .get(proposal_id)
                    .and_then(|p| {
                        p.get_update()
                            .cloned()
                            .map(|update| (p.content.sender.sender, update, proposal_id.clone()))
                    })
                    .ok_or(())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let removes = commit
            .removes
            .iter()
            .map(|proposal_id| {
                proposals_ids
                    .get(proposal_id)
                    .and_then(|p| p.get_remove().cloned())
                    .ok_or(())
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            sender,
            commit,
            confirmation,
            additions,
            updates,
            removes,
        })
    }
}
