use ra_client::EnclaveCertVerifierError;

use crate::ciphersuite::CipherSuiteTag;
use crate::extensions::ExtensionType;

/// Error type for key package verification.
#[derive(thiserror::Error, Debug)]
pub enum KeyPackageError {
    #[error("signature verify error: {0}")]
    SignatureVerifyError(ring::error::Unspecified),
    #[error("find extension error: {0}")]
    FindExtensionError(#[from] FindExtensionError),
    #[error("invalid supported versions")]
    InvalidSupportedVersions,
    #[error("invalid supported cipher suites")]
    InvalidSupportedCipherSuites,
    #[error("invalid credential, only support X509")]
    InvalidCredential,
    #[error("key package can't be used after timestamp: {0}")]
    NotAfter(u64),
    #[error("key package can't be used before timestamp: {0}")]
    NotBefore(u64),
    #[error("certificate verify error: {0}")]
    CertificateVerifyError(EnclaveCertVerifierError),
    #[error("unsupported cipher suite: {0}")]
    UnsupportedCipherSuite(CipherSuiteTag),
    #[error("Keypackage public keys don't match private keys")]
    KeypackageSecretDontMatch,
}

#[derive(thiserror::Error, Debug)]
pub enum TreeIntegrityError {
    #[error("keypackage verify failed: {0}")]
    KeyPackageVerifyFail(#[from] KeyPackageError),
    #[error("corrupted tree structure: {0}")]
    CorruptedTree(&'static str),
    #[error("children don't have parent hash")]
    ParentHashEmpty,
    #[error("parent hash value don't match")]
    ParentHashDontMatch,
    #[error("my_pos is invalid")]
    InvalidMyPos,
    #[error("tree should have at least one leaf node")]
    EmptyTree,
    #[error("node count overflow u32")]
    NodeCountOverflow,
    #[error("node count is not even number")]
    NodeCountNotEven,
    #[error("leaf node index is not even number")]
    LeafIndexIsNotEven,
    #[error("parent node index is not odd number")]
    ParentIndexIsNotOdd,
}

#[derive(thiserror::Error, Debug)]
#[error("({0:?}, {1})")]
pub struct FindExtensionError(pub(crate) ExtensionType, pub(crate) &'static str);

#[derive(thiserror::Error, Debug)]
pub enum CommitError {
    #[error("keypackage verify failed: {0}")]
    KeyPackageVerifyFail(#[from] KeyPackageError),
    #[error("find extension failed: {0}")]
    FindExtensionFail(#[from] FindExtensionError),
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
    #[error("commit self add proposal")]
    CommitSelfAdd,
}

#[derive(thiserror::Error, Debug)]
pub enum ProcessWelcomeError {
    #[error("hpke error: {0}")]
    HpkeError(#[from] hpke::HpkeError),
    #[error("keypackage verify failed: {0}")]
    KeyPackageVerifyFail(#[from] KeyPackageError),
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
    #[error("ratchet tree extension not found")]
    RatchetTreeNotFound(#[from] FindExtensionError),
    #[error("tree hash of the ratchet tree don't match the tree_hash field in the GroupInfo")]
    TreeHashDontMatch,
    #[error("process welcome message signed by self")]
    SelfWelcome,
    #[error("decrypted path secret don't match the public key")]
    PathSecretPublicKeyDontMatch,
}

#[derive(thiserror::Error, Debug)]
pub enum InitGroupError {
    #[error("keypackage verify failed: {0}")]
    KeyPackageVerifyFail(#[from] KeyPackageError),
    #[error("duplicate keypackages")]
    DuplicateKeyPackage,
    #[error("sign/verify signature error: {0}")]
    SignatureCryptographicError(#[from] ring::error::Unspecified),
    #[error("invalid secret length: {0}")]
    InvalidSecretLength(#[from] hkdf::InvalidLength),
    #[error("commit failed: {0}")]
    CommitError(#[from] CommitError),
}
