/// For specifying access control to TX data
pub mod access;
/// Different address types (Redeem and Tree/MAST)
pub mod address;
/// Miscellaneous TX attributes, such as network ID
pub mod attribute;
/// Transaction inputs (pointers to previous transaction outputs)
pub mod input;
/// Transaction outputs (amount to an address)
pub mod output;

use crate::common::{hash256, H256};
use crate::init::coin::{sum_coins, Coin, CoinError};
use crate::tx::data::{attribute::TxAttributes, input::TxoPointer, output::TxOut};
use blake2::Blake2s;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::fmt;

/// Calculates hash of the input data -- if RLP-serialized TX is passed in, it's equivalent to TxId.
/// Currently, it uses blake2s.
pub fn txid_hash(buf: &[u8]) -> H256 {
    hash256::<Blake2s>(buf)
}

/// Key to identify the used TXID hash function, e.g. in ProofOps.
pub const TXID_HASH_ID: &[u8; 7] = b"blake2s";

/// Transaction ID -- currently, blake2s hash of RLP-serialized TX data
pub type TxId = H256;

/// A Transaction containing tx inputs and tx outputs.
/// TODO: max input/output size?
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Tx {
    pub inputs: Vec<TxoPointer>,
    pub outputs: Vec<TxOut>,
    pub attributes: TxAttributes,
}

impl fmt::Display for Tx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for input in self.inputs.iter() {
            writeln!(f, "-> {}", input)?;
        }
        for output in self.outputs.iter() {
            writeln!(f, "   {} ->", output)?;
        }
        write!(f, "")
    }
}

impl Encodable for Tx {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append_list(&self.inputs)
            .append_list(&self.outputs)
            .append(&self.attributes);
    }
}

impl Decodable for Tx {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::Custom("Cannot decode a transaction"));
        }
        let inputs: Vec<TxoPointer> = rlp.list_at(0)?;
        let outputs: Vec<TxOut> = rlp.list_at(1)?;
        let attributes: TxAttributes = rlp.val_at(2)?;
        Ok(Tx::new_with(inputs, outputs, attributes))
    }
}

impl Tx {
    /// creates an empty TX
    pub fn new() -> Self {
        Tx::default()
    }

    /// creates a TX initialized with a provided vectors of inputs and outputs
    pub fn new_with(ins: Vec<TxoPointer>, outs: Vec<TxOut>, attr: TxAttributes) -> Self {
        Tx {
            inputs: ins,
            outputs: outs,
            attributes: attr,
        }
    }

    /// retrieves a TX ID (currently blake2s(rlp_bytes(tx)))
    pub fn id(&self) -> TxId {
        txid_hash(&self.rlp_bytes())
    }

    /// adds an input to a TX (mainly for testing / tools)
    pub fn add_input(&mut self, i: TxoPointer) {
        self.inputs.push(i)
    }

    /// adds an input to a TX (mainly for testing / tools)
    pub fn add_output(&mut self, o: TxOut) {
        self.outputs.push(o)
    }

    /// returns the total transaction output amount (sum of all output amounts)
    pub fn get_output_total(&self) -> Result<Coin, CoinError> {
        sum_coins(self.outputs.iter().map(|x| x.value))
    }
}
