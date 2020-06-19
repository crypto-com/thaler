#![deny(missing_docs, unsafe_code, unstable_features)]
//! This crate contains all the common types and utilities used by other `client-*` crates.
mod transaction;

pub mod cipher;
pub mod error;
pub mod key;
pub mod multi_sig_address;
pub mod seckey;
pub mod storage;
pub mod tendermint;

#[doc(inline)]
pub use crate::cipher::TransactionObfuscation;
#[doc(inline)]
pub use error::{Error, ErrorKind, Result, ResultExt};
#[doc(inline)]
pub use key::{PrivateKey, PrivateKeyAction, PublicKey};
#[doc(inline)]
pub use multi_sig_address::MultiSigAddress;
#[doc(inline)]
pub use seckey::SecKey;
#[doc(inline)]
pub use storage::{SecureStorage, Storage};
#[doc(inline)]
pub use transaction::{SignedTransaction, Transaction, TransactionInfo};

use secp256k1::{All, Secp256k1};

thread_local! {
    /// Thread local static Secp object
    pub static SECP: Secp256k1<All> = Secp256k1::new();
}
