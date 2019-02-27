use crate::common::TypeInfo;
use serde::de::{Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

pub const ECDSA_SIGNATURE_BYTES: usize = 65;

/// Transaction sign data (see Appendix F. "Signing Transactions" from Ethereum Yellow Paper)
/// adapted from emerald-rs
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EcdsaSignature {
    /// ‘recovery id’, a 1 byte value specifying the sign and finiteness of the curve point
    pub v: u8,

    /// ECDSA signature first point (0 < r < secp256k1n)
    pub r: [u8; 32],

    /// ECDSA signature second point (0 < s < secp256k1n ÷ 2 + 1)
    pub s: [u8; 32],
}

impl From<[u8; ECDSA_SIGNATURE_BYTES]> for EcdsaSignature {
    fn from(data: [u8; ECDSA_SIGNATURE_BYTES]) -> Self {
        let mut sign = EcdsaSignature::default();

        sign.v = data[0];
        sign.r.copy_from_slice(&data[1..=32]);
        sign.s.copy_from_slice(&data[(1 + 32)..(1 + 32 + 32)]);

        sign
    }
}

impl From<(u8, [u8; 32], [u8; 32])> for EcdsaSignature {
    fn from(data: (u8, [u8; 32], [u8; 32])) -> Self {
        EcdsaSignature {
            v: data.0,
            r: data.1,
            s: data.2,
        }
    }
}

impl Into<(u8, [u8; 32], [u8; 32])> for EcdsaSignature {
    fn into(self) -> (u8, [u8; 32], [u8; 32]) {
        (self.v, self.r, self.s)
    }
}

impl Into<String> for EcdsaSignature {
    fn into(self) -> String {
        format!(
            "0x{:X}{}{}",
            self.v,
            hex::encode(self.r),
            hex::encode(self.s)
        )
    }
}

impl TypeInfo for EcdsaSignature {
    #[inline]
    fn type_name() -> &'static str {
        "EcdsaSignature"
    }
}

impl Serialize for EcdsaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(EcdsaSignature::type_name(), &(self.v, self.r, self.s))
    }
}

impl<'de> Deserialize<'de> for EcdsaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EcdsaSignatureVisitor;

        impl<'de> Visitor<'de> for EcdsaSignatureVisitor {
            type Value = EcdsaSignature;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("recoverable ECDSA signature")
            }

            #[inline]
            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let sig_bytes =
                    <(u8, [u8; 32], [u8; 32]) as Deserialize>::deserialize(deserializer);
                sig_bytes.map(Into::into)
            }
        }

        deserializer.deserialize_newtype_struct(EcdsaSignature::type_name(), EcdsaSignatureVisitor)
    }
}
