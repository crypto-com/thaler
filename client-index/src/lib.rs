#![deny(missing_docs, unsafe_code, unstable_features)]
//! This crate exposes functionality to index transactions committed in Crypto.com Chain.

pub mod index;
pub mod service;

#[doc(inline)]
pub use crate::index::Index;
