//! Chain client errors
use std::fmt;

/// Alias of `Result` objects that return [`Error`]
///
/// [`Error`]: self::Error
pub type Result<T> = std::result::Result<T, Error>;

/// An opaque error type, used for all errors in this crate
pub struct Error {
    kind: ErrorKind,
    message: String,
    origin: Option<Box<dyn std::error::Error + 'static>>,
}

impl Error {
    /// Create a new `Error`
    #[inline]
    pub fn new<M>(kind: ErrorKind, message: M) -> Self
    where
        String: From<M>,
    {
        Error {
            kind,
            message: String::from(message),
            origin: None,
        }
    }

    /// Create a new `Error`
    #[inline]
    pub fn new_with_source<M>(
        kind: ErrorKind,
        message: M,
        origin: Box<dyn std::error::Error + 'static>,
    ) -> Self
    where
        String: From<M>,
    {
        Error {
            kind,
            message: String::from(message),
            origin: Some(origin),
        }
    }

    #[inline]
    /// Returns message
    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    /// Returns kind of error
    #[inline]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)?;

        if let Some(ref origin) = self.origin {
            writeln!(f)?;
            write!(f, " => {:?}", origin)?;
        }

        Ok(())
    }
}

impl std::error::Error for Error {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.origin.as_ref().map(AsRef::as_ref)
    }
}

/// Different variants of possible errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Initialization error
    InitializationError,
    /// Connection error
    ConnectionError,
    /// Storage error
    StorageError,
    /// Random number generation error
    RngError,
    /// Encryption error
    EncryptionError,
    /// Decryption error
    DecryptionError,
    /// Serialization error
    SerializationError,
    /// Deserialization error
    DeserializationError,
    /// Invalid input
    InvalidInput,
    /// Illegal input
    IllegalInput,
    /// Permission denied
    PermissionDenied,
    /// I/O error
    IoError,
    /// Tendermint RPC error
    TendermintRpcError,
    /// Multi-sig error
    MultiSigError,
    /// Internal error
    InternalError,
    /// Validator error
    ValidationError,
    /// Block data verify failed
    VerifyError,
    /// Run enclave error (gen keypackage)
    RunEnclaveError,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::InitializationError => write!(f, "Initialization error"),
            ErrorKind::ConnectionError => write!(f, "Connection error"),
            ErrorKind::StorageError => write!(f, "Storage error"),
            ErrorKind::RngError => write!(f, "Random number generation error"),
            ErrorKind::EncryptionError => write!(f, "Encryption error"),
            ErrorKind::DecryptionError => write!(f, "Decryption error"),
            ErrorKind::SerializationError => write!(f, "Serialization error"),
            ErrorKind::DeserializationError => write!(f, "Deserialization error"),
            ErrorKind::InvalidInput => write!(f, "Invalid input"),
            ErrorKind::IllegalInput => write!(f, "Illegal input"),
            ErrorKind::PermissionDenied => write!(f, "Permission denied"),
            ErrorKind::IoError => write!(f, "I/O error"),
            ErrorKind::TendermintRpcError => write!(f, "Tendermint RPC error"),
            ErrorKind::MultiSigError => write!(f, "Multi-sig error"),
            ErrorKind::InternalError => write!(f, "Internal error"),
            ErrorKind::ValidationError => write!(f, "Validation error"),
            ErrorKind::VerifyError => write!(f, "Verify error"),
            ErrorKind::RunEnclaveError => write!(f, "Run enclave error"),
        }
    }
}

impl From<ErrorKind> for Error {
    #[inline]
    fn from(kind: ErrorKind) -> Error {
        Error::new(kind, "")
    }
}

///Additional methods for `Result` and `Option`
pub trait ResultExt<T> {
    /// Adds given error kind and message to source error
    fn chain<F, M>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> (ErrorKind, M),
        String: From<M>;

    /// Adds given error kind and message to source error
    fn err_kind<F, M>(self, kind: ErrorKind, f: F) -> Result<T>
    where
        F: FnOnce() -> M,
        String: From<M>;
}

impl<T> ResultExt<T> for Option<T> {
    #[inline]
    fn chain<F, M>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> (ErrorKind, M),
        String: From<M>,
    {
        self.ok_or_else(|| {
            let (kind, message) = f();
            Error::new(kind, message)
        })
    }

    #[inline]
    fn err_kind<F, M>(self, kind: ErrorKind, f: F) -> Result<T>
    where
        F: FnOnce() -> M,
        String: From<M>,
    {
        self.chain(|| (kind, f()))
    }
}

impl<T, E> ResultExt<T> for std::result::Result<T, E>
where
    E: Into<Box<dyn std::error::Error + 'static>>,
{
    #[inline]
    fn chain<F, M>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> (ErrorKind, M),
        String: From<M>,
    {
        self.map_err(|err| {
            let (kind, message) = f();
            Error::new_with_source(kind, message, err.into())
        })
    }

    #[inline]
    fn err_kind<F, M>(self, kind: ErrorKind, f: F) -> Result<T>
    where
        F: FnOnce() -> M,
        String: From<M>,
    {
        self.chain(|| (kind, f()))
    }
}
