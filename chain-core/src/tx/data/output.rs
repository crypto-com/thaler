use std::fmt;

use parity_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::common::Timespec;
use crate::init::coin::Coin;
use crate::tx::data::address::ExtendedAddr;

/// Tx Output composed of an address and a coin value
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct TxOut {
    pub address: ExtendedAddr,
    pub value: Coin,
    pub valid_from: Option<Timespec>,
}

impl fmt::Display for TxOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.address, self.value)
    }
}

impl TxOut {
    /// creates a TX output (mainly for testing/tools)
    pub fn new(address: ExtendedAddr, value: Coin) -> Self {
        TxOut {
            address,
            value,
            valid_from: None,
        }
    }

    /// creates a TX output with timelock
    pub fn new_with_timelock(address: ExtendedAddr, value: Coin, valid_from: Timespec) -> Self {
        TxOut {
            address,
            value,
            valid_from: Some(valid_from),
        }
    }
}
