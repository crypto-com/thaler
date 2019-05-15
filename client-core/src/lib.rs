#![deny(missing_docs, unsafe_code, unstable_features)]
//! # Crypto.com Chain Client
//!
//! This crate exposes following functionalities for interacting with Crypto.com Chain:
//! - Wallet creation
//! - Address generation
//! - Transaction syncing and storage
//! - Balance tracking
//! - Transaction creation and signing (WIP)
//! - Transaction broadcasting (WIP)
pub mod key;
pub mod service;
pub mod transaction_builder;
pub mod wallet;

#[doc(inline)]
pub use key::{PrivateKey, PublicKey};
#[doc(inline)]
pub use transaction_builder::TransactionBuilder;
#[doc(inline)]
pub use wallet::WalletClient;

use secp256k1::{All, Secp256k1};

thread_local! { pub(crate) static SECP: Secp256k1<All> = Secp256k1::new(); }
