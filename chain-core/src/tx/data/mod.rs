use std::prelude::v1::Vec;

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

use std::fmt;

use blake2::Blake2s;
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::common::{hash256, H256};
use crate::init::coin::{sum_coins, Coin, CoinError};
use crate::tx::data::{attribute::TxAttributes, input::TxoPointer, output::TxOut};
use crate::tx::TransactionId;

/// Calculates hash of the input data -- if SCALE-serialized TX is passed in, it's equivalent to TxId.
/// Currently, it uses blake2s.
pub fn txid_hash(buf: &[u8]) -> H256 {
    hash256::<Blake2s>(buf)
}

/// Key to identify the used TXID hash function, e.g. in ProofOps.
pub const TXID_HASH_ID: &[u8; 7] = b"blake2s";

/// Transaction ID -- currently, blake2s hash of SCALE-serialized TX data
pub type TxId = H256;

/// A Transaction containing tx inputs and tx outputs.
/// TODO: max input/output size?
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
#[derive(Debug, Default, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

impl TransactionId for Tx {}

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
