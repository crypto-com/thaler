#![deny(missing_docs, unsafe_code, unstable_features)]
//! This crate exposes functionality to index transactions committed in Crypto.com Chain.
pub mod auto_synchronizer;
pub mod cipher;
pub mod handler;
pub mod index;
pub mod service;
pub mod synchronizer;

#[doc(inline)]
pub use crate::cipher::TransactionObfuscation;
#[doc(inline)]
pub use crate::handler::{BlockHandler, TransactionHandler};
#[doc(inline)]
pub use crate::index::Index;
#[doc(inline)]
pub use crate::service::{AddressDetails, AddressMemento};
