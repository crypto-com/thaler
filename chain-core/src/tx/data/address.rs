use parity_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::common::H256;
use crate::init::address::RedeemAddress;
use crate::state::account::StakedStateAddress;

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

impl ExtendedAddr {
    /// Returns true if current address is redeem address, false otherwise.
    pub fn is_redeem(&self) -> bool {
        match self {
            ExtendedAddr::BasicRedeem(_) => true,
            ExtendedAddr::OrTree(_) => false,
        }
    }

    /// Returns true if current address is tree address, false otherwise.
    pub fn is_tree(&self) -> bool {
        match self {
            ExtendedAddr::BasicRedeem(_) => false,
            ExtendedAddr::OrTree(_) => true,
        }
    }
}

impl fmt::Display for ExtendedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtendedAddr::BasicRedeem(addr) => write!(f, "{}", addr),
            ExtendedAddr::OrTree(hash) => write!(f, "TODO (base58) 0x{}", hex::encode(hash)),
        }
    }
}

// TODO: remove BasicRedeem from ExtendedAddr?
impl From<StakedStateAddress> for ExtendedAddr {
    fn from(addr: StakedStateAddress) -> Self {
        match addr {
            StakedStateAddress::BasicRedeem(address) => ExtendedAddr::BasicRedeem(address),
        }
    }
}
