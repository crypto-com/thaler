use parity_scale_codec::{Decode, Encode, Error, Input, Output};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::de;
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(not(feature = "mesalock_sgx"))]
use std::fmt;
use std::prelude::v1::Vec;

use crate::tx::data::access::TxAccessPolicy;

/// Tx extra metadata, e.g. network ID
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct TxAttributes {
    /// the network identifier
    #[cfg_attr(
        not(feature = "mesalock_sgx"),
        serde(serialize_with = "serialize_chain_hex_id")
    )]
    #[cfg_attr(
        not(feature = "mesalock_sgx"),
        serde(deserialize_with = "deserialize_chain_hex_id")
    )]
    pub chain_hex_id: u8,
    /// who is allowed to view the transaction content (enforced by tx-query)
    pub allowed_view: Vec<TxAccessPolicy>,
    /// the global chain-core app version that the transaction was generated with
    pub app_version: u64,
}

impl Encode for TxAttributes {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        dest.push_byte(0);
        dest.push_byte(self.chain_hex_id);
        dest.push(&self.allowed_view);
        dest.push(&self.app_version);
    }

    fn size_hint(&self) -> usize {
        self.chain_hex_id.size_hint()
            + self.allowed_view.size_hint()
            + self.app_version.size_hint()
            + 1
    }
}

impl Decode for TxAttributes {
    fn decode<DecIn: Input>(input: &mut DecIn) -> Result<Self, Error> {
        let tag = input.read_byte()?;
        if tag != 0 {
            return Err(Error::from("Unsupported TxAttributes variant"));
        }
        let chain_hex_id = input.read_byte()?;
        let allowed_view: Vec<TxAccessPolicy> = Vec::decode(input)?;
        let app_version = u64::decode(input)?;
        Ok(TxAttributes {
            chain_hex_id,
            allowed_view,
            app_version,
        })
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
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

#[cfg(not(feature = "mesalock_sgx"))]
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
            app_version: crate::APP_VERSION,
        }
    }

    /// creates tx attributes with access policy
    pub fn new_with_access(chain_hex_id: u8, allowed_view: Vec<TxAccessPolicy>) -> Self {
        TxAttributes {
            chain_hex_id,
            allowed_view,
            app_version: crate::APP_VERSION,
        }
    }
}
