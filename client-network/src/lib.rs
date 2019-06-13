#![deny(missing_docs, unsafe_code, unstable_features)]
//! Crypto.com Chain currently has two realms:
//!
//! - Payments
//! - Network Operations
//!
//! This crate provides and easy to use client for performing network operations on Crypto.com Chain. Payments, on the
//! other hand, are handled by `WalletClient` in `client-core` crate.
pub mod network_ops;

#[doc(inline)]
pub use self::network_ops::NetworkOpsClient;
