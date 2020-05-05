#[cfg(not(feature = "mesalock_sgx"))]
use crate::init::address::ErrorAddress;
use crate::init::address::RedeemAddress;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::convert::From;
#[cfg(not(feature = "mesalock_sgx"))]
use std::convert::TryFrom;
#[cfg(not(feature = "mesalock_sgx"))]
use std::fmt;
#[cfg(not(feature = "mesalock_sgx"))]
use std::str::FromStr;

/// StakedState address type
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum StakedStateAddress {
    /// needs ecdsa witness
    BasicRedeem(RedeemAddress),
}

impl Encode for StakedStateAddress {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        match *self {
            StakedStateAddress::BasicRedeem(ref ra) => {
                dest.push_byte(0);
                dest.push(ra);
            }
        }
    }

    fn size_hint(&self) -> usize {
        match self {
            StakedStateAddress::BasicRedeem(ref addr) => addr.size_hint() + 1,
        }
    }
}

impl Decode for StakedStateAddress {
    fn decode<DecIn: Input>(input: &mut DecIn) -> Result<Self, Error> {
        let tag = input.read_byte()?;
        match tag {
            0 => {
                let addr = RedeemAddress::decode(input)?;
                Ok(StakedStateAddress::BasicRedeem(addr))
            }
            _ => Err("No such variant in enum StakedStateAddress".into()),
        }
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl Serialize for StakedStateAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl<'de> Deserialize<'de> for StakedStateAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrVisitor;

        impl<'de> de::Visitor<'de> for StrVisitor {
            type Value = StakedStateAddress;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("staking address")
            }

            #[inline]
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                StakedStateAddress::from_str(value)
                    .map_err(|err| de::Error::custom(err.to_string()))
            }
        }

        deserializer.deserialize_str(StrVisitor)
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl TryFrom<&[u8]> for StakedStateAddress {
    type Error = ErrorAddress;

    fn try_from(c: &[u8]) -> Result<Self, Self::Error> {
        let addr = RedeemAddress::try_from(c)?;
        Ok(StakedStateAddress::BasicRedeem(addr))
    }
}

impl From<RedeemAddress> for StakedStateAddress {
    fn from(addr: RedeemAddress) -> Self {
        StakedStateAddress::BasicRedeem(addr)
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for StakedStateAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StakedStateAddress::BasicRedeem(a) => write!(f, "{}", a),
        }
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl FromStr for StakedStateAddress {
    type Err = ErrorAddress;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(StakedStateAddress::BasicRedeem(RedeemAddress::from_str(s)?))
    }
}

impl AsRef<[u8]> for StakedStateAddress {
    fn as_ref(&self) -> &[u8] {
        match self {
            StakedStateAddress::BasicRedeem(a) => &a,
        }
    }
}
