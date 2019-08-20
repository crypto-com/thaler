use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::de;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::prelude::v1::Vec;

use crate::tx::data::access::TxAccessPolicy;

/// Tx extra metadata, e.g. network ID
#[derive(Debug, Default, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxAttributes {
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_chain_hex_id"))]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "deserialize_chain_hex_id")
    )]
    pub chain_hex_id: u8,
    pub allowed_view: Vec<TxAccessPolicy>,
    // TODO: other attributes, e.g. versioning info
}

#[cfg(feature = "serde")]
#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_chain_hex_id<S>(
    chain_hex_id: &u8,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode_upper(vec![*chain_hex_id]))
}

#[cfg(feature = "serde")]
fn deserialize_chain_hex_id<'de, D>(deserializer: D) -> std::result::Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    struct StrVisitor;

    impl<'de> de::Visitor<'de> for StrVisitor {
        type Value = u8;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("view key in hexadecimal string")
        }

        #[inline]
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let view_key_vec =
                hex::decode(value).map_err(|err| de::Error::custom(err.to_string()))?;
            if view_key_vec.len() != 1 {
                return Err(de::Error::custom(format!(
                    "Invalid chain hex id length: {}",
                    view_key_vec.len()
                )));
            }

            Ok(view_key_vec[0])
        }
    }

    deserializer.deserialize_str(StrVisitor)
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
