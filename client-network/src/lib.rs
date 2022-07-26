#![deny(missing_docs, unsafe_code, unstable_features)]
//! Thaler Experimental Network currently has two realms:
//!
//! - Payments
//! - Network Operations
//!
//! This crate provides and easy to use client for performing network operations on Thaler Experimental Network. Payments, on the
//! other hand, are handled by `WalletClient` in `client-core` crate.
pub mod network_ops;

#[doc(inline)]
pub use self::network_ops::NetworkOpsClient;
