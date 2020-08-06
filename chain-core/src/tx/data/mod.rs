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

use parity_scale_codec::{Decode, Encode, Error, Input, Output};

use serde::{Deserialize, Serialize};

use crate::common::H256;
use crate::init::coin::{sum_coins, Coin, CoinError};
use crate::tx::data::{attribute::TxAttributes, input::TxoPointer, output::TxOut};
#[cfg(feature = "new-txid")]
use crate::tx::TaggedTransaction;
#[cfg(not(feature = "new-txid"))]
use crate::tx::TransactionId;

/// Each input is 34 bytes
/// Each output is 33 (address) + 8 (amount) + 9 (timelock) = 50 bytes
/// Assuming maximum allowed view keys are 64. Attributes are 1 + (64 * 42) = 2688 bytes
///
/// Assuming maximum inputs and outputs allowed are 64 each,
/// So, maximum transaction size (34 * 64) + (50 * 64) + 2688 = 8064
const MAX_TX_SIZE: usize = 8100; // 8100 bytes

/// Key to identify the used TXID hash function, e.g. in ProofOps.
pub const TXID_HASH_ID: &[u8; 6] = b"blake3";

/// Transaction ID -- currently, blake3 hash of SCALE-serialized TX data
pub type TxId = H256;

/// A Transaction containing tx inputs and tx outputs.
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Tx {
    /// previous transaction outputs to be spent
    pub inputs: Vec<TxoPointer>,
    /// new transaction outputs
    pub outputs: Vec<TxOut>,
    /// versioning and network info + access info (who can see the TX content)
    pub attributes: TxAttributes,
}

impl Encode for Tx {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        dest.push(&self.inputs);
        dest.push(&self.outputs);
        dest.push(&self.attributes);
    }

    fn size_hint(&self) -> usize {
        self.inputs.size_hint() + self.outputs.size_hint() + self.attributes.size_hint()
    }
}

impl Decode for Tx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let size = input
            .remaining_len()?
            .ok_or_else(|| "Unable to calculate size of input")?;

        if size > MAX_TX_SIZE {
            return Err("Input too large".into());
        }

        let inputs = <Vec<TxoPointer>>::decode(input)?;
        let outputs = <Vec<TxOut>>::decode(input)?;
        let attributes = TxAttributes::decode(input)?;

        Ok(Tx {
            inputs,
            outputs,
            attributes,
        })
    }
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

#[cfg(not(feature = "new-txid"))]
impl TransactionId for Tx {}

#[cfg(feature = "new-txid")]
impl From<Tx> for TaggedTransaction {
    fn from(tx: Tx) -> TaggedTransaction {
        TaggedTransaction::Transfer(tx)
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
