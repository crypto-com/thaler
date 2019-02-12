use common::TypeInfo;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::fmt;
use tx::data::TxId;

/// Structure used for addressing a specific output of a transaction
/// built from a TxId (hash of the tx) and the offset in the outputs of this
/// transaction.
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
pub struct TxoPointer {
    pub id: TxId,
    pub index: usize,
}

impl fmt::Display for TxoPointer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}@{}",
            serde_json::to_string(&self.id).unwrap(),
            self.index
        )
    }
}

impl TypeInfo for TxoPointer {
    #[inline]
    fn type_name() -> &'static str {
        "TxoPointer"
    }
}

/// TODO: switch to cbor_event or equivalent simple raw cbor library when serialization is finalized
/// TODO: backwards/forwards-compatible serialization (adding/removing fields, variants etc. should be possible)
impl Serialize for TxoPointer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct(TxoPointer::type_name(), 2)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("index", &self.index)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for TxoPointer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxoPointerVisitor;

        impl<'de> Visitor<'de> for TxoPointerVisitor {
            type Value = TxoPointer;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("tx input pointer")
            }

            #[inline]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let txid = match map.next_entry::<u64, TxId>()? {
                    Some((0, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("txid")),
                };
                let index = match map.next_entry::<u64, usize>()? {
                    Some((1, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("index")),
                };
                Ok(TxoPointer::new(txid, index))
            }
        }

        deserializer.deserialize_struct(
            TxoPointer::type_name(),
            &["txid", "index"],
            TxoPointerVisitor,
        )
    }
}

impl TxoPointer {
    /// Constructs a new TX input (mainly for testing/tools).
    pub fn new(id: TxId, index: usize) -> Self {
        TxoPointer { id, index }
    }
}
