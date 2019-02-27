use crate::common::TypeInfo;
use crate::tx::data::access::TxAccessPolicy;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::fmt;

/// Tx extra metadata, e.g. network ID
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TxAttributes {
    pub chain_hex_id: u8,
    pub allowed_view: Vec<TxAccessPolicy>,
    // TODO: other attributes, e.g. versioning info
}

impl TypeInfo for TxAttributes {
    #[inline]
    fn type_name() -> &'static str {
        "TxAttributes"
    }
}

/// TODO: switch to cbor_event or equivalent simple raw cbor library when serialization is finalized
/// TODO: backwards/forwards-compatible serialization (adding/removing fields, variants etc. should be possible)
impl Serialize for TxAttributes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct(TxAttributes::type_name(), 2)?;
        s.serialize_field("chain_hex_id", &self.chain_hex_id)?;
        s.serialize_field("allowed_view", &self.allowed_view)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for TxAttributes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxAttributesVisitor;

        impl<'de> Visitor<'de> for TxAttributesVisitor {
            type Value = TxAttributes;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("transaction attributes")
            }

            #[inline]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let chain_hex_id = match map.next_entry::<u64, u8>()? {
                    Some((0, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("chain_hex_id")),
                };
                let allowed_view = match map.next_entry::<u64, Vec<TxAccessPolicy>>()? {
                    Some((1, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("allowed_view")),
                };
                Ok(TxAttributes::new_with_access(chain_hex_id, allowed_view))
            }
        }
        deserializer.deserialize_struct(
            TxAttributes::type_name(),
            &["chain_hex_id", "allowed_view"],
            TxAttributesVisitor,
        )
    }
}

impl TxAttributes {
    /// creates tx attributes
    pub fn new(chain_hex_id: u8) -> Self {
        TxAttributes {
            chain_hex_id,
            allowed_view: Vec::new(),
        }
    }

    /// creates tx attributes with access policy
    pub fn new_with_access(chain_hex_id: u8, allowed_view: Vec<TxAccessPolicy>) -> Self {
        TxAttributes {
            chain_hex_id,
            allowed_view,
        }
    }
}
