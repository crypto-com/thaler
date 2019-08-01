use parity_scale_codec::{Decode, Encode, Error, Input, Output};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::prelude::v1::Vec;

use crate::tx::data::access::TxAccessPolicy;

/// Tx extra metadata, e.g. network ID
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxAttributes {
    pub chain_hex_id: u8,
    pub allowed_view: Vec<TxAccessPolicy>,
    // TODO: other attributes, e.g. versioning info
}

impl Encode for TxAttributes {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        dest.push_byte(0);
        dest.push_byte(2);
        dest.push_byte(self.chain_hex_id);
        self.allowed_view.encode_to(dest);
    }
}

impl Decode for TxAttributes {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let tag = input.read_byte()?;
        let constructor_len = input.read_byte()?;
        match (tag, constructor_len) {
            (0, 2) => {
                let chain_hex_id: u8 = input.read_byte()?;
                let allowed_view: Vec<TxAccessPolicy> = Vec::decode(input)?;
                Ok(TxAttributes::new_with_access(chain_hex_id, allowed_view))
            }
            _ => Err(Error::from("Invalid tag and length")),
        }
    }
}

impl TxAttributes {
    /// creates tx attributes
    pub fn new(chain_hex_id: u8) -> Self {
        TxAttributes {
            chain_hex_id,
            allowed_view: Vec::new(),
        }
    }

    /// creates tx attributes with access policy
    pub fn new_with_access(chain_hex_id: u8, allowed_view: Vec<TxAccessPolicy>) -> Self {
        TxAttributes {
            chain_hex_id,
            allowed_view,
        }
    }
}
