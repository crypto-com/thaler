use crate::common::TypeInfo;
use crate::init::MAX_COIN;
use serde::de::{Deserialize, Deserializer, Error, Visitor};
use serde::ser::{Serialize, Serializer};
use std::{fmt, ops, result};

// adapted from rust-cardano
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Coin(u64);

/// error type relating to `Coin` operations
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum CoinError {
    /// means that the given value was out of bound
    ///
    /// Max bound being: `MAX_COIN`.
    OutOfBound(u64),

    ParseIntError,

    Negative,
}

impl fmt::Display for CoinError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CoinError::OutOfBound(ref v) => write!(
                f,
                "Coin of value {} is out of bound. Max coin value: {}.",
                v, MAX_COIN
            ),
            CoinError::ParseIntError => write!(f, "Cannot parse a valid integer"),
            CoinError::Negative => write!(f, "Coin cannot hold a negative value"),
        }
    }
}

impl ::std::error::Error for CoinError {}

type CoinResult = Result<Coin, CoinError>;

impl Coin {
    /// create a coin of value `0`.
    pub fn zero() -> Self {
        Coin(0)
    }

    /// create of unitary coin (a coin of value `1`)
    pub fn unit() -> Self {
        Coin(1)
    }

    /// create of maximum coin
    pub fn max() -> Self {
        Coin(MAX_COIN)
    }

    /// create a coin of the given value
    pub fn new(v: u64) -> CoinResult {
        if v <= MAX_COIN {
            Ok(Coin(v))
        } else {
            Err(CoinError::OutOfBound(v))
        }
    }
}

impl ::std::ops::Deref for Coin {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Coin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // 8 decimals
        write!(f, "{}.{:08}", self.0 / 100_000_000, self.0 % 100_000_000)
    }
}

impl ::std::str::FromStr for Coin {
    type Err = CoinError;
    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        let v: u64 = match s.parse() {
            Err(_) => return Err(CoinError::ParseIntError),
            Ok(v) => v,
        };
        Coin::new(v)
    }
}

impl ops::Add for Coin {
    type Output = CoinResult;
    fn add(self, other: Coin) -> Self::Output {
        Coin::new(self.0 + other.0)
    }
}
impl<'a> ops::Add<&'a Coin> for Coin {
    type Output = CoinResult;
    fn add(self, other: &'a Coin) -> Self::Output {
        Coin::new(self.0 + other.0)
    }
}
impl ops::Sub for Coin {
    type Output = CoinResult;
    fn sub(self, other: Coin) -> Self::Output {
        if other.0 > self.0 {
            Err(CoinError::Negative)
        } else {
            Ok(Coin(self.0 - other.0))
        }
    }
}
impl<'a> ops::Sub<&'a Coin> for Coin {
    type Output = CoinResult;
    fn sub(self, other: &'a Coin) -> Self::Output {
        if other.0 > self.0 {
            Err(CoinError::Negative)
        } else {
            Ok(Coin(self.0 - other.0))
        }
    }
}
// this instance is necessary to chain the substraction operations
//
// i.e. `coin1 - coin2 - coin3`
impl ops::Sub<Coin> for CoinResult {
    type Output = CoinResult;
    fn sub(self, other: Coin) -> Self::Output {
        if other.0 > self?.0 {
            Err(CoinError::Negative)
        } else {
            Ok(Coin(self?.0 - other.0))
        }
    }
}

impl From<Coin> for u64 {
    fn from(c: Coin) -> u64 {
        c.0
    }
}

impl From<u32> for Coin {
    fn from(c: u32) -> Coin {
        Coin(u64::from(c))
    }
}

impl TypeInfo for Coin {
    #[inline]
    fn type_name() -> &'static str {
        "Coin"
    }
}

impl Serialize for Coin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(Coin::type_name(), &self.0)
    }
}

impl<'de> Deserialize<'de> for Coin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoinVisitor;

        impl<'de> Visitor<'de> for CoinVisitor {
            type Value = Coin;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("the coin amount in a range (0..total supply]")
            }

            #[inline]
            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let amount = <u64 as Deserialize>::deserialize(deserializer);
                match amount {
                    Ok(v) if v <= MAX_COIN => Ok(Coin(v)),
                    Ok(v) => Err(D::Error::custom(format!("{}", CoinError::OutOfBound(v)))),
                    Err(e) => Err(e),
                }
            }
        }

        deserializer.deserialize_newtype_struct(Coin::type_name(), CoinVisitor)
    }
}

pub fn sum_coins<I>(coin_iter: I) -> CoinResult
where
    I: Iterator<Item = Coin>,
{
    coin_iter.fold(Coin::new(0), |acc, ref c| acc.and_then(|v| v + *c))
}

#[cfg(test)]
mod test {
    use super::*;
    use quickcheck::quickcheck;

    quickcheck! {
        // test a given u32 is always a valid value for a `Coin`
        fn coin_from_u32_always_valid(v: u32) -> bool {
            Coin::new(v as u64).is_ok()
        }

    }
}
