use parity_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::common::H256;
use crate::init::address::RedeemAddress;

/// TODO: opaque types?
type TreeRoot = H256;

/// Currently, only Ethereum-style redeem address + MAST of Or operations (records the root).
/// TODO: HD-addresses?
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum ExtendedAddr {
    BasicRedeem(RedeemAddress),
    OrTree(TreeRoot),
}

impl fmt::Display for ExtendedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtendedAddr::BasicRedeem(addr) => write!(f, "{}", addr),
            ExtendedAddr::OrTree(hash) => write!(f, "TODO (base58) 0x{}", hex::encode(hash)),
        }
    }
}
