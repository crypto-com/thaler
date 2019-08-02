use std::fmt;

use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::tx::data::TxId;

// TODO: u16 and Vec size check in Decode implementation
pub type TxoIndex = u64;

/// Structure used for addressing a specific output of a transaction
/// built from a TxId (hash of the tx) and the offset in the outputs of this
/// transaction.
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxoPointer {
    pub id: TxId,
    // TODO: u16 and Vec size check in Decode implementation
    pub index: TxoIndex,
}

impl fmt::Display for TxoPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}@{}", self.id, self.index)
    }
}

impl TxoPointer {
    /// Constructs a new TX input (mainly for testing/tools).
    pub fn new(id: TxId, index: usize) -> Self {
        TxoPointer {
            id,
            index: index as TxoIndex,
        }
    }
}
