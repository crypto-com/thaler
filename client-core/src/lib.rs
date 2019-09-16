#![deny(missing_docs, unsafe_code, unstable_features)]
//! # Crypto.com Chain Client
//!
//! This crate provides `WalletClient` trait which is responsible for interacting with transaction index and provide
//! following functionalities on per-wallet basis:
//!
//! - Wallet creation
//! - Address generation
//! - Balance tracking
//! - Transaction history
//! - Transaction creation and signing (with automatic unspent transaction selection)
pub mod auto_sync;
pub mod auto_sync_core;
pub mod auto_sync_data;
pub mod auto_synchronizer;
pub mod cipher;
pub mod handler;
pub mod index;
pub mod input_selection;
pub mod service;
pub mod signer;
pub mod synchronizer;
pub mod transaction_builder;
pub mod unspent_transactions;
pub mod wallet;

#[doc(inline)]
pub use crate::cipher::TransactionObfuscation;
#[doc(inline)]
pub use crate::handler::{BlockHandler, TransactionHandler};
#[doc(inline)]
pub use crate::index::Index;
#[doc(inline)]
pub use crate::input_selection::InputSelectionStrategy;
#[doc(inline)]
pub use crate::service::{AddressDetails, AddressMemento};
#[doc(inline)]
pub use crate::signer::Signer;
#[doc(inline)]
pub use crate::transaction_builder::TransactionBuilder;
#[doc(inline)]
pub use crate::unspent_transactions::{SelectedUnspentTransactions, UnspentTransactions};
#[doc(inline)]
pub use crate::wallet::{MultiSigWalletClient, WalletClient};
