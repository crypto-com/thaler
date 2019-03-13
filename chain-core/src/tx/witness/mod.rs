/// Witness for the initial "redeem" (ECDSA with PK recovery)
pub mod redeem;
/// Witness for Merklized Abstract Syntax Trees (MAST) + Schnorr
pub mod tree;

use crate::common::TypeInfo;
use crate::tx::witness::{
    redeem::EcdsaSignature,
    tree::{ProofOp, RawPubkey, RawSignature},
};
use serde::de::{Deserialize, Deserializer, EnumAccess, Error, VariantAccess, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

/// A transaction witness is a vector of input witnesses
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TxWitness(Vec<TxInWitness>);

impl TypeInfo for TxWitness {
    #[inline]
    fn type_name() -> &'static str {
        "TxWitness"
    }
}

impl Serialize for TxWitness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(TxWitness::type_name(), &self.0)
    }
}

impl<'de> Deserialize<'de> for TxWitness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxWitnessVisitor;

        impl<'de> Visitor<'de> for TxWitnessVisitor {
            type Value = TxWitness;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("TX witness")
            }

            #[inline]
            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let address_bytes = <Vec<TxInWitness>>::deserialize(deserializer);
                address_bytes.map(TxWitness)
            }
        }

        deserializer.deserialize_newtype_struct(TxWitness::type_name(), TxWitnessVisitor)
    }
}

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
pub enum TxInWitness {
    BasicRedeem(EcdsaSignature),
    TreeSig(RawPubkey, RawSignature, Vec<ProofOp>),
}

impl fmt::Display for TxInWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TypeInfo for TxInWitness {
    #[inline]
    fn type_name() -> &'static str {
        "TxInWitness"
    }
}

impl Serialize for TxInWitness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            TxInWitness::BasicRedeem(ref sig) => serializer.serialize_newtype_variant(
                TxInWitness::type_name(),
                0,
                "BasicRedeem",
                sig,
            ),
            TxInWitness::TreeSig(pk, sig, ops) => serializer.serialize_newtype_variant(
                TxInWitness::type_name(),
                1,
                "TreeSig",
                &(pk, sig, ops),
            ),
        }
    }
}

impl<'de> Deserialize<'de> for TxInWitness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxInWitnessVisitor;
        impl<'de> Visitor<'de> for TxInWitnessVisitor {
            type Value = TxInWitness;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("transaction input witness")
            }

            #[inline]
            fn visit_enum<A>(self, deserializer: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                match deserializer.variant::<u64>() {
                    Ok((0, v)) => VariantAccess::newtype_variant::<EcdsaSignature>(v)
                        .map(TxInWitness::BasicRedeem),
                    Ok((1, v)) => {
                        VariantAccess::newtype_variant::<(RawPubkey, RawSignature, Vec<ProofOp>)>(v)
                            .map(|(pk, sig, ops)| TxInWitness::TreeSig(pk, sig, ops))
                    }
                    Ok((i, _)) => Err(A::Error::unknown_variant(
                        &i.to_string(),
                        &["BasicRedeem", "TreeSig"],
                    )),
                    Err(e) => Err(e),
                }
            }
        }

        deserializer.deserialize_enum(
            TxInWitness::type_name(),
            &["BasicRedeem", "TreeSig"],
            TxInWitnessVisitor,
        )
    }
}
