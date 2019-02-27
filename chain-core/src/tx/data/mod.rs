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

use crate::common::{hash256, TypeInfo, HASH_SIZE_256};
use crate::init::coin::{sum_coins, Coin, CoinError};
use crate::tx::data::{attribute::TxAttributes, input::TxoPointer, output::TxOut};
use blake2::Blake2s;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use serde_cbor::ser::to_vec_packed;
use std::fmt;

/// Calculates hash of the input data -- if CBOR-serialized TX is passed in, it's equivalent to TxId.
/// Currently, it uses blake2s.
pub fn txid_hash(buf: &[u8]) -> [u8; HASH_SIZE_256] {
    hash256::<Blake2s>(buf)
}

/// Key to identify the used TXID hash function, e.g. in ProofOps.
pub const TXID_HASH_ID: &[u8; 7] = b"blake2s";

/// Transaction ID -- currently, blake2s hash of CBOR-serialized TX data
/// TODO: opaque types?
pub type TxId = [u8; HASH_SIZE_256];

/// A Transaction containing tx inputs and tx outputs.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Tx {
    pub inputs: Vec<TxoPointer>,
    pub outputs: Vec<TxOut>,
    pub attributes: TxAttributes,
}

impl fmt::Display for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for input in self.inputs.iter() {
            writeln!(f, "-> {}", input)?;
        }
        for output in self.outputs.iter() {
            writeln!(f, "   {} ->", output)?;
        }
        write!(f, "")
    }
}

impl TypeInfo for Tx {
    #[inline]
    fn type_name() -> &'static str {
        "Tx"
    }
}

/// TODO: switch to cbor_event or equivalent simple raw cbor library when serialization is finalized
/// TODO: backwards/forwards-compatible serialization (adding/removing fields, variants etc. should be possible)
impl Serialize for Tx {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct(Tx::type_name(), 3)?;
        s.serialize_field("inputs", &self.inputs)?;
        s.serialize_field("outputs", &self.outputs)?;
        s.serialize_field("attributes", &self.attributes)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for Tx {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxVisitor;

        impl<'de> Visitor<'de> for TxVisitor {
            type Value = Tx;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("transaction data")
            }

            #[inline]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let inputs = match map.next_entry::<u64, Vec<TxoPointer>>()? {
                    Some((0, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("inputs")),
                };
                let outputs = match map.next_entry::<u64, Vec<TxOut>>()? {
                    Some((1, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("outputs")),
                };
                let attributes = match map.next_entry::<u64, TxAttributes>()? {
                    Some((2, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("attributes")),
                };
                Ok(Tx::new_with(inputs, outputs, attributes))
            }
        }
        deserializer.deserialize_struct(
            Tx::type_name(),
            &["inputs", "outputs", "attributes"],
            TxVisitor,
        )
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

    /// retrieves a TX ID (currently blake2s(cbor_serialize_packed(tx)))
    pub fn id(&self) -> TxId {
        let s = to_vec_packed(self).expect("Tx can be serialiazed to CBOR");
        txid_hash(&s)
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
