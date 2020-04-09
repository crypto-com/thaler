#[cfg(not(feature = "mesalock_sgx"))]
use std::fmt;
#[cfg(not(feature = "mesalock_sgx"))]
use std::str::FromStr;

use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use secp256k1::key::PublicKey;
#[cfg(not(feature = "mesalock_sgx"))]
use serde::de;
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::common::H264;

/// What can be accessed in TX (enforced by enclave code in HW)
/// Initial schema will only allow access to all TX data,
/// but this may later be extended to restrict to e.g. particular tx outputs
/// or metadata
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub enum TxAccess {
    /// everything can be accessed
    AllData,
}

impl Default for TxAccess {
    fn default() -> Self {
        TxAccess::AllData
    }
}

impl Decode for TxAccess {
    fn decode<DecIn: Input>(input: &mut DecIn) -> Result<Self, Error> {
        let tag = input.read_byte()?;
        // NOTE: tag 1 likely reserved for txout restriction
        match tag {
            0 => Ok(TxAccess::AllData),
            _ => Err("No such variant in enum TxAccess".into()),
        }
    }
}

impl Encode for TxAccess {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        match *self {
            TxAccess::AllData => {
                dest.push_byte(0);
            }
        }
    }

    fn size_hint(&self) -> usize {
        // NOTE: revisit if extended
        1
    }
}

/// Specifies who can access what
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct TxAccessPolicy {
    /// the corresponding private key is used for authentication
    /// in tx-query protocol
    #[cfg_attr(
        not(feature = "mesalock_sgx"),
        serde(serialize_with = "serialize_view_key")
    )]
    #[cfg_attr(
        not(feature = "mesalock_sgx"),
        serde(deserialize_with = "deserialize_view_key")
    )]
    pub view_key: PublicKey,
    /// what can be accessed
    pub access: TxAccess,
}

#[cfg(not(feature = "mesalock_sgx"))]
fn serialize_view_key<S>(
    view_key: &PublicKey,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let view_key_string = format!("{}", view_key);
    serializer.serialize_str(&view_key_string)
}

#[cfg(not(feature = "mesalock_sgx"))]
fn deserialize_view_key<'de, D>(deserializer: D) -> std::result::Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    struct StrVisitor;

    impl<'de> de::Visitor<'de> for StrVisitor {
        type Value = PublicKey;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("view key in hexadecimal string")
        }

        #[inline]
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            PublicKey::from_str(value).map_err(|err| de::Error::custom(err.to_string()))
        }
    }

    deserializer.deserialize_str(StrVisitor)
}

impl Encode for TxAccessPolicy {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.view_key.serialize().encode_to(dest);
        self.access.encode_to(dest);
    }

    fn size_hint(&self) -> usize {
        33 + self.access.size_hint()
    }
}

impl Decode for TxAccessPolicy {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let view_key_bytes = H264::decode(input)?;
        let view_key = PublicKey::from_slice(&view_key_bytes)
            .map_err(|_| Error::from("Unable to parse public key"))?;
        let access = TxAccess::decode(input)?;
        Ok(TxAccessPolicy::new(view_key, access))
    }
}

impl TxAccessPolicy {
    /// creates tx access policy
    pub fn new(view_key: PublicKey, access: TxAccess) -> Self {
        TxAccessPolicy { view_key, access }
    }
}
