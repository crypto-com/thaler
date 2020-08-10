//! This crate implements [mls protocol](https://github.com/mlswg/mls-protocol/blob/d1d5f56a5d83781042d19c830497ab5aa104907f/draft-ietf-mls-protocol.md)
//! Note: "Application Secret Tree" is not implemented here, as it's not being used in the latest
//! TDBE iteration: https://github.com/crypto-com/chain-docs/blob/master/docs/modules/tdbe.md#new-obfuscation-key
//! (i.e. instead of exchanging application messages, only node tree ratcheting + secret derivations are used,
//! as the obfuscation key for transactions is obtained directly using the MLS "exporter" construct that didn't exist in the earlier protocol drafts)

#![warn(clippy::wildcard_imports)]
pub mod ciphersuite;
pub mod credential;
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

pub use keypackage::{KeyPackage, KeyPackageSecret};
pub use rustls::internal::msgs::codec::{self, Codec, Reader};
