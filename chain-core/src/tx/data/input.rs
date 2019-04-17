use std::fmt;

use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};

use crate::tx::data::TxId;

/// Structure used for addressing a specific output of a transaction
/// built from a TxId (hash of the tx) and the offset in the outputs of this
/// transaction.
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct TxoPointer {
    pub id: TxId,
    pub index: usize,
}

impl fmt::Display for TxoPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}@{}", self.id, self.index)
    }
}

impl Encodable for TxoPointer {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2).append(&self.id).append(&self.index);
    }
}

impl Decodable for TxoPointer {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::Custom("Cannot decode a transaction input"));
        }
        let id: TxId = rlp.val_at(0)?;
        let index: usize = rlp.val_at(1)?;
        Ok(TxoPointer::new(id, index))
    }
}

impl TxoPointer {
    /// Constructs a new TX input (mainly for testing/tools).
    pub fn new(id: TxId, index: usize) -> Self {
        TxoPointer { id, index }
    }
}
