pub use crate::hdwallet::ChainPathError;

#[derive(Debug, Clone, Eq, PartialEq)]
/// Error code for hdwallet
pub enum Error {
    /// Index is out of range
    KeyIndexOutOfRange,
    /// ChainPathError
    ChainPath(ChainPathError),
    /// secp256k1 errors
    Secp(secp256k1::Error),
}

impl From<ChainPathError> for Error {
    fn from(err: ChainPathError) -> Error {
        Error::ChainPath(err)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Error {
        Error::Secp(err)
    }
}
