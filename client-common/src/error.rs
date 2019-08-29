//! Chain client errors
use std::fmt;

use failure::{Backtrace, Context, Fail};

/// Alias of `Result` objects that return [`Error`]
///
/// [`Error`]: self::Error
pub type Result<T> = std::result::Result<T, Error>;

/// An opaque error type, used for all errors in this crate
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

/// Different variants of possible errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// Storage initialization error
    #[fail(display = "Storage initialization error")]
    StorageInitializationError,
    /// Other storage error
    #[fail(display = "Storage error")]
    StorageError,
    /// Key generation error
    #[fail(display = "Key generation error")]
    KeyGenerationError,
    /// Random number generator error
    #[fail(display = "Random number generator error")]
    RngError,
    /// Decryption error
    #[fail(display = "Decryption error")]
    DecryptionError,
    /// Already exists in storage
    #[fail(display = "Already exists in storage")]
    AlreadyExists,
    /// Serialization error
    #[fail(display = "Serialization error")]
    SerializationError,
    /// Deserialization error
    #[fail(display = "Deserialization error")]
    DeserializationError,
    /// Wallet not found
    #[fail(display = "Wallet not found")]
    WalletNotFound,
    /// Address not found
    #[fail(display = "Address not found")]
    AddressNotFound,
    /// Error while locking a shared resource
    #[fail(display = "Error while locking a shared resource")]
    LockError,
    /// Error while adding two balances
    #[fail(display = "Error while adding two balances")]
    BalanceAdditionError,
    /// Balance not found
    #[fail(display = "Balance not found")]
    BalanceNotFound,
    /// RPC error
    #[fail(display = "RPC error")]
    RpcError,
    /// Invalid transaction
    #[fail(display = "Invalid transaction")]
    InvalidTransaction,
    /// Transaction not found
    #[fail(display = "Transaction not found")]
    TransactionNotFound,
    /// Output not found
    #[fail(display = "Output not found")]
    OutputNotFound,
    /// Private key not found
    #[fail(display = "Private key not found")]
    PrivateKeyNotFound,
    /// Insufficient balance
    #[fail(display = "Insufficient balance")]
    InsufficientBalance,
    /// IO error
    #[fail(display = "IO error")]
    IoError,
    /// Invalid input
    #[fail(display = "Invalid input")]
    InvalidInput,
    /// Permission denied
    #[fail(display = "Permission denied")]
    PermissionDenied,
    /// Multi-sig session not found
    #[fail(display = "Multi-sig session not found")]
    SessionNotFound,
    /// Co-signer not found
    #[fail(display = "Co-signer not found")]
    SignerNotFound,
    /// Session creation error
    #[fail(display = "Session creation error")]
    SessionCreationError,
    /// Missing nonce commitment
    #[fail(display = "Missing nonce commitment")]
    MissingNonceCommitment,
    /// Missing nonce
    #[fail(display = "Missing nonce")]
    MissingNonce,
    /// Missing partial signature
    #[fail(display = "Missing partial signature")]
    MissingPartialSignature,
    /// Nonce combining error
    #[fail(display = "Nonce combining error")]
    NonceCombiningError,
    /// Partial signature computation error
    #[fail(display = "Partial signature computation error")]
    PartialSignError,
    /// Signing error
    #[fail(display = "Signing error")]
    SigningError,
    /// Invalid certificate
    #[fail(display = "Invalid certificate format in TLS")]
    InvalidCertFormat,
    /// Bad attestation report
    #[fail(display = "Bad SGX attestation report")]
    BadAttnReport,
    /// Webpki check failure
    #[fail(display = "Webpki check failure")]
    WebpkiFailure,
    /// TDQE connection failure
    #[fail(display = "Transaction decryption enclave connection failure")]
    TDQEConnectionError,
    /// Multisig error
    #[fail(display = "Invalid self public key in wallet multisig address")]
    MultiSigInvalidSelfPubKey,
    /// Transaction validation failure
    #[fail(display = "Transaction validation failed")]
    TransactionValidationFailed,
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl Error {
    /// Returns [`ErrorKind`] of current error
    ///
    /// [`ErrorKind`]: self::ErrorKind
    pub fn kind(&self) -> ErrorKind {
        *self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}
