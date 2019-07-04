use parity_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::common::{H256, HASH_SIZE_256};

/// TODO: opaque types?
type TreeRoot = H256;

/// Currently, only Ethereum-style redeem address + MAST of Or operations (records the root).
/// TODO: HD-addresses?
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExtendedAddr {
    OrTree(TreeRoot),
}

impl fmt::Display for ExtendedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // TODO: base58 for encoding addresses
            ExtendedAddr::OrTree(hash) => write!(f, "0x{}", hex::encode(hash)),
        }
    }
}

impl FromStr for ExtendedAddr {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let address = if s.starts_with("0x") {
            s.split_at(2).1
        } else {
            s
        };

        let decoded = hex::decode(&address)?;

        if decoded.len() != HASH_SIZE_256 {
            return Err(hex::FromHexError::InvalidStringLength);
        }

        let mut tree_root = [0; HASH_SIZE_256];
        tree_root.copy_from_slice(&decoded);

        Ok(ExtendedAddr::OrTree(tree_root))
    }
}
