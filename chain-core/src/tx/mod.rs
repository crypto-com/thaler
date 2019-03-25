/// Transaction internal structure
pub mod data;
/// Witness structures (e.g. signatures) for transactions
pub mod witness;

use self::data::Tx;
use self::witness::TxWitness;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TxAux {
    /// Tx with the vector of witnesses
    TransferTx(Tx, TxWitness),
}

impl TxAux {
    /// creates a new Tx with a vector of witnesses (mainly for testing/tools)
    pub fn new(tx: Tx, witness: TxWitness) -> Self {
        TxAux::TransferTx(tx, witness)
    }
}

impl fmt::Display for TxAux {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxAux::TransferTx(tx, witness) => {
                writeln!(f, "Tx:\n{}", tx)?;
                writeln!(f, "witnesses: {:?}\n", witness)
            }
        }
    }
}

impl Encodable for TxAux {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            TxAux::TransferTx(tx, witness) => {
                s.begin_list(3).append(&0u8).append(tx).append(witness);
            }
        }
    }
}

impl Decodable for TxAux {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        // TODO: this item count will be a range once there are more TX types
        if rlp.item_count()? != 3 {
            return Err(DecoderError::Custom(
                "Cannot decode a transaction auxiliary structure",
            ));
        }
        let type_tag: u8 = rlp.val_at(0)?;
        match type_tag {
            0 => {
                let tx: Tx = rlp.val_at(1)?;
                let witness = rlp.val_at(2)?;
                Ok(TxAux::TransferTx(tx, witness))
            }
            _ => Err(DecoderError::Custom("Unknown transaction type")),
        }
    }
}
