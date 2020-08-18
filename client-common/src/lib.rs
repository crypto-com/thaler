// `proc_macro_hygiene` -- strange that this works OK / isn't required on stable Rust (1.45.2)
#![cfg_attr(
    all(target_os = "linux", not(feature = "mock-enclave")),
    feature(proc_macro_hygiene)
)]
#![deny(missing_docs, unsafe_code)]
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
pub use transaction::{temporary_mls_init, SignedTransaction, Transaction, TransactionInfo};
