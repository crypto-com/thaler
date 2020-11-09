//! This crate implements [mls protocol](https://github.com/mlswg/mls-protocol/blob/1d5e14d79435834bc5cab6c7aa9e2fcdd6afeabc/draft-ietf-mls-protocol.md)
//! Note: "Application Secret Tree" is not implemented here, as it's not being used in the latest
//! TDBE iteration: https://github.com/crypto-com/thaler-docs/blob/master/docs/modules/tdbe.md#new-obfuscation-key
//! (i.e. instead of exchanging application messages, only node tree ratcheting + secret derivations are used,
//! as the obfuscation key for transactions is obtained directly using the MLS "exporter" construct that didn't exist in the earlier protocol drafts)

#![warn(clippy::wildcard_imports)]
pub mod ciphersuite;
pub mod credential;
pub mod crypto;
pub mod error;
pub mod extensions;
pub mod extras;
pub mod group;
pub mod key;
pub mod keypackage;
pub mod message;
pub mod secrets;
pub mod tree;
pub mod tree_math;
pub mod utils;

pub use ciphersuite::DefaultCipherSuite;
pub use keypackage::{KeyPackage, KeyPackageSecret};
pub use rustls::internal::msgs::codec::{self, Codec, Reader};
