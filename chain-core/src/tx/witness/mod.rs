/// Witness for Merklized Abstract Syntax Trees (MAST) + Schnorr
pub mod tree;

use std::fmt;
use std::prelude::v1::Vec;
use serde::{Deserialize, Serialize};
use parity_codec::{Decode, Encode, Input, Output};
// TODO: switch to normal signatures + explicit public key
use secp256k1::{self, recovery::RecoverableSignature, schnorrsig::SchnorrSignature};

use crate::common::Proof;
use crate::tx::witness::tree::{RawPubkey, RawSignature};

pub type EcdsaSignature = RecoverableSignature;

/// A transaction witness is a vector of input witnesses
#[derive(Debug, Default, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxWitness(Vec<TxInWitness>);

impl TxWitness {
    /// creates an empty witness (for testing/tools)
    pub fn new() -> Self {
        TxWitness::default()
    }
}
impl From<Vec<TxInWitness>> for TxWitness {
    fn from(v: Vec<TxInWitness>) -> Self {
        TxWitness(v)
    }
}
impl ::std::iter::FromIterator<TxInWitness> for TxWitness {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = TxInWitness>,
    {
        TxWitness(Vec::from_iter(iter))
    }
}
impl ::std::ops::Deref for TxWitness {
    type Target = Vec<TxInWitness>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ::std::ops::DerefMut for TxWitness {
    fn deref_mut(&mut self) -> &mut Vec<TxInWitness> {
        &mut self.0
    }
}

// normally should be some structure: e.g. indicate a type of signature
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TxInWitness {
    TreeSig(SchnorrSignature, Proof<RawPubkey>),
}

impl fmt::Display for TxInWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Encode for TxInWitness {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        match *self {
            TxInWitness::TreeSig(ref schnorrsig, ref proof) => {
                dest.push_byte(0);
                dest.push_byte(3);
                let serialized_sig: RawSignature = schnorrsig.serialize_default();
                serialized_sig.encode_to(dest);
                proof.encode_to(dest);
            }
        }
    }
}

impl Decode for TxInWitness {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let tag = input.read_byte()?;
        let constructor_len = input.read_byte()?;
        match (tag, constructor_len) {
            (0, 3) => {
                let raw_sig = RawSignature::decode(input)?;
                let schnorrsig = SchnorrSignature::from_default(&raw_sig).ok()?;
                let proof = Proof::decode(input)?;
                Some(TxInWitness::TreeSig(schnorrsig, proof))
            }
            _ => None,
        }
    }
}
