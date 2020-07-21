///! This module contains additional parts that are a part of the MLS draft spec,
///! but are required for resolving relevant open issues in the draft spec
///! or for extra conventions / operations: https://github.com/crypto-com/chain-docs/blob/master/docs/modules/tdbe.md.

/// module for external validation
mod validation;

pub use validation::{check_nodejoin, NodeJoinError, NodeJoinResult};
