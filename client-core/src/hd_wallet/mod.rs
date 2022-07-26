//! # HD Wallet
//! adapted from https://github.com/jjyr/hdwallet (HDWallet)
//! Copyright (c) 2018 - 2020, Jiang Jinyang (licensed under the MIT License)
//! Modifications Copyright (c) 2018-2020 Crypto.com (licensed under the Apache License, Version 2.0)
//!
/// error code for hdwallet
pub mod error;
/// entended key for hdwallet
pub mod extended_key;
/// key-chain for hdwallet
pub mod key_chain;
/// traits for hdwallet
pub mod traits;

mod wallet_kind;

pub use wallet_kind::HardwareKind;

pub use crate::hd_wallet::extended_key::{
    key_index::KeyIndex, ExtendedPrivKey, ExtendedPubKey, KeySeed,
};
pub use crate::hd_wallet::key_chain::{
    chain_path::{ChainPath, Error as ChainPathError, SubPath},
    DefaultKeyChain, Derivation, KeyChain,
};
