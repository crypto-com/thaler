use crate::common::TypeInfo;
use crate::tx::witness::tree::RawPubkey;
use serde::de::{Deserialize, Deserializer, EnumAccess, Error, MapAccess, VariantAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::fmt;

/// What can be access in TX -- TODO: revisit when enforced by HW encryption / enclaves
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TxAccess {
    AllData,
    Output(usize),
    // TODO: other components?
    // TODO: TX ID could be computed as a root of a merkle tree from different TX components?
}

impl Default for TxAccess {
    fn default() -> Self {
        TxAccess::AllData
    }
}

impl TypeInfo for TxAccess {
    #[inline]
    fn type_name() -> &'static str {
        "TxAccess"
    }
}

impl Serialize for TxAccess {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            TxAccess::AllData => {
                serializer.serialize_unit_variant(TxAccess::type_name(), 0, "AllData")
            }
            TxAccess::Output(ref index) => {
                serializer.serialize_newtype_variant(TxAccess::type_name(), 1, "Output", &index)
            }
        }
    }
}

impl<'de> Deserialize<'de> for TxAccess {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxAccessVisitor;
        impl<'de> Visitor<'de> for TxAccessVisitor {
            type Value = TxAccess;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("transaction access specification")
            }

            #[inline]
            fn visit_enum<A>(self, deserializer: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                match deserializer.variant::<u64>() {
                    Ok((0, _)) => Ok(TxAccess::AllData),
                    Ok((1, v)) => VariantAccess::newtype_variant::<usize>(v).map(TxAccess::Output),
                    Ok((i, _)) => Err(A::Error::unknown_variant(
                        &i.to_string(),
                        &["AllData", "Output"],
                    )),
                    Err(e) => Err(e),
                }
            }
        }

        deserializer.deserialize_enum(
            TxAccess::type_name(),
            &["AllData", "Output"],
            TxAccessVisitor,
        )
    }
}

/// Specifies who can access what -- TODO: revisit when enforced by HW encryption / enclaves
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TxAccessPolicy {
    pub view_key: RawPubkey,
    pub access: TxAccess,
}

impl TxAccessPolicy {
    /// creates tx access policy
    pub fn new(view_key: RawPubkey, access: TxAccess) -> Self {
        TxAccessPolicy { view_key, access }
    }
}

impl TypeInfo for TxAccessPolicy {
    #[inline]
    fn type_name() -> &'static str {
        "TxAccessPolicy"
    }
}

/// TODO: switch to cbor_event or equivalent simple raw cbor library when serialization is finalized
/// TODO: backwards/forwards-compatible serialization (adding/removing fields, variants etc. should be possible)
impl Serialize for TxAccessPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct(TxAccessPolicy::type_name(), 2)?;
        s.serialize_field("view_key", &self.view_key)?;
        s.serialize_field("access", &self.access)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for TxAccessPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxAccessPolicyVisitor;

        impl<'de> Visitor<'de> for TxAccessPolicyVisitor {
            type Value = TxAccessPolicy;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("transaction access policy")
            }

            #[inline]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let view_key = match map.next_entry::<u64, RawPubkey>()? {
                    Some((0, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("view_key")),
                };
                let access = match map.next_entry::<u64, TxAccess>()? {
                    Some((1, v)) => v,
                    _ => return Err(serde::de::Error::missing_field("access")),
                };
                Ok(TxAccessPolicy::new(view_key, access))
            }
        }
        deserializer.deserialize_struct(
            TxAccessPolicy::type_name(),
            &["view_key", "access"],
            TxAccessPolicyVisitor,
        )
    }
}
