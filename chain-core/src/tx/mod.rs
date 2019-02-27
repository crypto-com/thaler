/// Transaction internal structure
pub mod data;
/// Witness structures (e.g. signatures) for transactions
pub mod witness;

use self::data::Tx;
use self::witness::TxWitness;
use crate::common::TypeInfo;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::fmt;

/// Tx with the vector of witnesses
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxAux {
    pub tx: Tx,
    pub witness: TxWitness,
}

impl TxAux {
    /// creates a new Tx with a vector of witnesses (mainly for testing/tools)
    pub fn new(tx: Tx, witness: TxWitness) -> Self {
        TxAux { tx, witness }
    }
}

impl fmt::Display for TxAux {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Tx:\n{}", self.tx)?;
        writeln!(f, "witnesses: {:?}\n", self.witness)
    }
}

impl TypeInfo for TxAux {
    #[inline]
    fn type_name() -> &'static str {
        "TxAux"
    }
}

/// TODO: switch to cbor_event or equivalent simple raw cbor library when serialization is finalized
/// TODO: backwards/forwards-compatible serialization (adding/removing fields, variants etc. should be possible)
impl Serialize for TxAux {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct(TxAux::type_name(), 2)?;
        s.serialize_field("tx", &self.tx)?;
        s.serialize_field("witness", &self.witness)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for TxAux {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxAuxVisitor;

        impl<'de> Visitor<'de> for TxAuxVisitor {
            type Value = TxAux;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("TX auxiliary structure")
            }

            #[inline]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let tx = match map.next_entry::<u64, Tx>()? {
                    Some((0, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("tx")),
                };
                let witness = match map.next_entry::<u64, TxWitness>()? {
                    Some((1, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("witness")),
                };
                Ok(TxAux::new(tx, witness))
            }
        }

        deserializer.deserialize_struct(TxAux::type_name(), &["tx", "witness"], TxAuxVisitor)
    }
}
