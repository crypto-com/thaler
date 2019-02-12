use common::{TypeInfo, HASH_SIZE_256};
use init::address::RedeemAddressRaw;
use serde::de::{Deserialize, Deserializer, EnumAccess, Error, VariantAccess, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

/// TODO: opaque types?
pub type TreeRoot = [u8; HASH_SIZE_256];

/// Currently, only Ethereum-style redeem address + MAST of Or operations (records the root).
/// TODO: HD-addresses?
#[derive(Debug, PartialEq, PartialOrd, Ord, Hash, Eq, Clone)]
pub enum ExtendedAddr {
    BasicRedeem(RedeemAddressRaw),
    OrTree(TreeRoot),
}

impl fmt::Display for ExtendedAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExtendedAddr::BasicRedeem(addr) => write!(f, "0x{}", hex::encode(addr)),
            ExtendedAddr::OrTree(hash) => write!(f, "TODO (base58) 0x{}", hex::encode(hash)),
        }
    }
}

impl TypeInfo for ExtendedAddr {
    #[inline]
    fn type_name() -> &'static str {
        "ExtendedAddr"
    }
}

impl Serialize for ExtendedAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ExtendedAddr::BasicRedeem(ref addr) => serializer.serialize_newtype_variant(
                ExtendedAddr::type_name(),
                0,
                "BasicRedeem",
                addr,
            ),
            ExtendedAddr::OrTree(ref hash) => {
                serializer.serialize_newtype_variant(ExtendedAddr::type_name(), 1, "OrTree", hash)
            }
        }
    }
}

impl<'de> Deserialize<'de> for ExtendedAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ExtendedAddrVisitor;
        impl<'de> Visitor<'de> for ExtendedAddrVisitor {
            type Value = ExtendedAddr;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("extended address")
            }

            #[inline]
            fn visit_enum<A>(self, deserializer: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                match deserializer.variant::<u64>() {
                    Ok((0, v)) => VariantAccess::newtype_variant::<RedeemAddressRaw>(v)
                        .map(ExtendedAddr::BasicRedeem),
                    Ok((1, v)) => {
                        VariantAccess::newtype_variant::<TreeRoot>(v).map(ExtendedAddr::OrTree)
                    }
                    Ok((i, _)) => Err(A::Error::unknown_variant(
                        &i.to_string(),
                        &["BasicRedeem", "OrTree"],
                    )),
                    Err(e) => Err(e),
                }
            }
        }

        deserializer.deserialize_enum(
            ExtendedAddr::type_name(),
            &["BasicRedeem", "OrTree"],
            ExtendedAddrVisitor,
        )
    }
}
