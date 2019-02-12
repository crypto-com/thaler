use std::{error, fmt, io};

#[derive(Debug)]
pub enum Error {
    /// Command execution error
    ExecError(String),
}

macro_rules! from_err {
    ($x:ty) => {
        impl From<$x> for Error {
            fn from(err: $x) -> Self {
                Error::ExecError(err.to_string())
            }
        }
    };
}

from_err!(io::Error);
from_err!(rand::Error);
from_err!(secp256k1zkp::Error);
from_err!(miscreant::error::Error);
from_err!(hex::FromHexError);
from_err!(serde_cbor::error::Error);
from_err!(std::num::ParseIntError);
from_err!(chain_core::init::coin::CoinError);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ExecError(ref str) => write!(f, "Command execution error: {}", str),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Command execution error"
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            _ => None,
        }
    }
}

pub type ExecResult = Result<(), Error>;

pub const NONCE_SIZE: usize = 8;

/// Request passphrase
pub fn request_passphrase() -> Result<String, Error> {
    let passphrase = rpassword::read_password_from_tty(Some("Enter passphrase: "));
    passphrase.map_err(|e| Error::ExecError(e.to_string()))
}
