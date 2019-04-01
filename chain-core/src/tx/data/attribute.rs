use crate::tx::data::access::TxAccessPolicy;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

/// Tx extra metadata, e.g. network ID
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TxAttributes {
    pub chain_hex_id: u8,
    pub allowed_view: Vec<TxAccessPolicy>,
    // TODO: other attributes, e.g. versioning info
}

impl Encodable for TxAttributes {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&self.chain_hex_id)
            .append_list(&self.allowed_view);
    }
}

impl Decodable for TxAttributes {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        // TODO: this item count will be a range once there are more TX types
        if rlp.item_count()? != 2 {
            return Err(DecoderError::Custom("Cannot decode transaction attributes"));
        }
        let chain_hex_id: u8 = rlp.val_at(0)?;
        let allowed_view: Vec<TxAccessPolicy> = rlp.list_at(1)?;
        Ok(TxAttributes::new_with_access(chain_hex_id, allowed_view))
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
