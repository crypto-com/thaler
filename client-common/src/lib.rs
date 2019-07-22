#![deny(missing_docs, unsafe_code, unstable_features)]
//! This crate contains all the common types and utilities used by other `client-*` crates.
mod block_header;
mod transaction;

pub mod balance;
pub mod error;
pub mod key;
pub mod storage;
pub mod tendermint;

#[doc(inline)]
pub use block_header::BlockHeader;
#[doc(inline)]
pub use error::{Error, ErrorKind, Result};
#[doc(inline)]
pub use key::{PrivateKey, PublicKey};
#[doc(inline)]
pub use storage::{SecureStorage, Storage};
#[doc(inline)]
pub use transaction::Transaction;

use secp256k1::{All, Secp256k1};

thread_local! {
    /// Thread local static Secp object
    pub static SECP: Secp256k1<All> = Secp256k1::new();
}
