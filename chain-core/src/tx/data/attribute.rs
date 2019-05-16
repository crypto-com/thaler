use parity_codec_derive::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::tx::data::access::TxAccessPolicy;

/// Tx extra metadata, e.g. network ID
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct TxAttributes {
    pub chain_hex_id: [u8; 1],
    pub allowed_view: Vec<TxAccessPolicy>,
    // TODO: other attributes, e.g. versioning info
}

impl TxAttributes {
    /// creates tx attributes
    pub fn new(chain_hex_id: u8) -> Self {
        TxAttributes {
            chain_hex_id: [chain_hex_id],
            allowed_view: Vec::new(),
        }
    }

    /// creates tx attributes with access policy
    pub fn new_with_access(chain_hex_id: u8, allowed_view: Vec<TxAccessPolicy>) -> Self {
        TxAttributes {
            chain_hex_id: [chain_hex_id],
            allowed_view,
        }
    }
}
