use crate::key::PublicKey;
use crate::keypackage::{CipherSuite, KeyPackage, ProtocolVersion};

/// spec: draft-ietf-mls-protocol.md#Add
pub struct Add {
    key_package: KeyPackage,
}

/// spec: draft-ietf-mls-protocol.md#Update
/// FIXME
#[allow(dead_code)]
pub struct Update {
    key_package: KeyPackage,
}

/// spec: draft-ietf-mls-protocol.md#Remove
/// FIXME
#[allow(dead_code)]
pub struct Remove {
    removed: u32,
}

/// spec: draft-ietf-mls-protocol.md#Proposal
/// #[repr(u8)]
pub enum Proposal {
    // Invalid = 0,
    Add(Add),       // = 1,
    Update(Update), // = 2,
    Remove(Remove), // = 3,
}

/// spec: draft-ietf-mls-protocol.md#Message-Framing
/// + draft-ietf-mls-protocol.md#MContent-Signing-and-Encryption
pub struct MLSPlaintextCommon {
    /// 0..255 bytes -- application-defined id
    pub group_id: Vec<u8>,
    /// version of the group key
    /// (incremented by 1 for each Commit message
    /// that is processed)
    pub epoch: u64,
    pub sender: Sender,
    pub content: ContentType,
}

/// spec: draft-ietf-mls-protocol.md#Message-Framing
pub struct MLSPlaintext {
    pub content: MLSPlaintextCommon,
    /// 0..2^16-1
    pub signature: Vec<u8>,
}

impl MLSPlaintext {
    pub fn get_add_keypackage(&self) -> Option<KeyPackage> {
        match &self.content.content {
            ContentType::Proposal(Proposal::Add(Add { key_package })) => Some(key_package.clone()),
            _ => None,
        }
    }
}

/// 0..255 -- hash of the MLSPlaintext in which the Proposal was sent
/// spec: draft-ietf-mls-protocol.md#Commit
pub type ProposalId = Vec<u8>;

/// spec: draft-ietf-mls-protocol.md#Commit
pub struct Commit {
    /// 0..2^16-1
    pub updates: Vec<ProposalId>,
    /// 0..2^16-1
    pub removes: Vec<ProposalId>,
    /// 0..2^16-1
    pub adds: Vec<ProposalId>,
    /// 0..2^16-1
    /// "path field of a Commit message MUST be populated if the Commit covers at least one Update or Remove proposal"
    /// "path field MUST also be populated if the Commit covers no proposals at all (i.e., if all three proposal vectors are empty)."
    pub path: Option<DirectPath>,
}

/// spec: draft-ietf-mls-protocol.md#Welcoming-New-Members
pub struct Welcome {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    /// 0..2^32-1
    pub secrets: Vec<EncryptedGroupSecrets>,
    /// 0..2^32-1
    pub encrypted_group_info: Vec<u8>,
}

/// spec: draft-ietf-mls-protocol.md#Welcoming-New-Members
pub struct EncryptedGroupSecrets {
    pub encrypted_group_secrets: HPKECiphertext,
    pub key_package_hash: Vec<u8>,
}

/// spec: draft-ietf-mls-protocol.md#Direct-Paths
pub struct HPKECiphertext {
    /// 0..2^16-1
    pub kem_output: Vec<u8>,
    /// 0..2^16-1
    pub ciphertext: Vec<u8>,
}

/// spec: draft-ietf-mls-protocol.md#Direct-Paths
pub struct DirectPathNode {
    pub public_key: PublicKey,
    /// 0..0..2^32-1>
    pub encrypted_path_secret: Vec<HPKECiphertext>,
}

/// spec: draft-ietf-mls-protocol.md#Direct-Paths
pub struct DirectPath {
    pub leaf_key_package: KeyPackage,
    /// 0..0..2^16-1>
    pub nodes: Vec<DirectPathNode>,
}

/// spec: draft-ietf-mls-protocol.md#Message-Framing
/// #[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum ContentType {
    Application {
        // <0..2^32-1>
        application_data: Vec<u8>,
    }, //= 1,
    Proposal(Proposal), //= 2,
    Commit {
        commit: Commit,
        // 0..255
        confirmation: Vec<u8>,
    }, //= 3,
}

/// spec: draft-ietf-mls-protocol.md#Message-Framing
#[repr(u8)]
pub enum SenderType {
    Member = 1,
    Preconfigured = 2,
    NewMember = 3,
}

/// spec: draft-ietf-mls-protocol.md#Message-Framing
pub struct Sender {
    pub sender_type: SenderType,
    pub sender: u32,
}
