//! # Value with associated properties (e.g. min/max bounds)
//! adapted from https://github.com/input-output-hk/rust-cardano (Cardano Rust)
//! Copyright (c) 2018, Input Output HK (licensed under the MIT License)
//! Modifications Copyright (c) 2018 - 2019, Foris Limited (licensed under the Apache License, Version 2.0)

use parity_codec::{Decode, Encode, Input};
use serde::de::{Deserialize, Deserializer, Error, Visitor};
use serde::{Serialize, Serializer};
use std::{fmt, mem, ops, result, slice};

use crate::init::{MAX_COIN, MAX_COIN_DECIMALS};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Encode)]
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    /// create of base unitary coin (a coin of value `1`)
    pub fn unit() -> Self {
        Coin(1)
    }

    /// create of non-base coin of value 1 (assuming 8 decimals)
    pub fn one() -> Self {
        Coin(MAX_COIN_DECIMALS)
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

impl fmt::Display for Coin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 8 decimals
        write!(
            f,
            "{}.{:08}",
            self.0 / MAX_COIN_DECIMALS,
            self.0 % MAX_COIN_DECIMALS
        )
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

impl Serialize for Coin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let coin_string = self.0.to_string();
        serializer.serialize_str(&coin_string[..])
    }
}

impl<'de> Deserialize<'de> for Coin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrVisitor;

        impl<'de> Visitor<'de> for StrVisitor {
            type Value = Coin;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("the coin amount in a range (0..total supply]")
            }

            #[inline]
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let amount = value
                    .parse::<u64>()
                    .map_err(|e| E::custom(format!("{}", e)))?;
                Coin::new(amount).map_err(|e| E::custom(format!("{}", e)))
            }
        }

        deserializer.deserialize_str(StrVisitor)
    }
}

// impl<'de> Deserialize<'de> for Coin {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         struct CoinVisitor;

//         impl<'de> Visitor<'de> for CoinVisitor {
//             type Value = Coin;
//             fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
//                 formatter.write_str("the coin amount in a range (0..total supply]")
//             }

//             #[inline]
//             fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
//             where
//                 D: Deserializer<'de>,
//             {
//                 let amount = <u64 as Deserialize>::deserialize(deserializer);
//                 match amount {
//                     Ok(v) if v <= MAX_COIN => Ok(Coin(v)),
//                     Ok(v) => Err(D::Error::custom(format!("{}", CoinError::OutOfBound(v)))),
//                     Err(e) => Err(e),
//                 }
//             }
//         }
//         deserializer.deserialize_newtype_struct("Coin", CoinVisitor)
//     }
// }

impl Decode for Coin {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let size = mem::size_of::<u64>();
        let mut val: u64 = unsafe { mem::zeroed() };
        unsafe {
            let raw: &mut [u8] = slice::from_raw_parts_mut(&mut val as *mut u64 as *mut u8, size);
            if input.read(raw) != size {
                return None;
            }
        }
        if val > MAX_COIN {
            None
        } else {
            Some(Coin(val))
        }
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

    mod serializer_deserializer_test {
        use super::*;
        use serde_json;

        #[test]
        fn test_serialize_to_string_should_work() {
            let coin = Coin::new(99999).expect("Unable to create new coin");

            let json = serde_json::to_string(&coin).expect("Unable to serialize Coin");
            assert_eq!(json, "\"99999\"");
        }

        #[test]
        fn test_serialize_large_coin_to_string_should_work() {
            let coin = Coin::new(10000000000000000000).expect("Unable to create new coin");

            let json = serde_json::to_string(&coin).expect("Unable to serialize Coin");
            assert_eq!(json, "\"10000000000000000000\"");
        }

        #[test]
        fn test_deserialize_from_number_should_give_error() {
            let deserialize_result = serde_json::from_str::<Coin>("99999");

            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_empty_string_should_give_error() {
            let deserialize_result = serde_json::from_str::<Coin>("\"\"");

            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_out_of_range_should_give_error() {
            let deserialize_result = serde_json::from_str::<Coin>("\"10000000000000000001\"");

            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_negative_should_give_error() {
            let deserialize_result = serde_json::from_str::<Coin>("\"-1\"");

            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_hexadecimal_should_give_error() {
            let deserialize_result = serde_json::from_str::<Coin>("\"0xAB\"");
            assert!(deserialize_result.is_err());

            let deserialize_result = serde_json::from_str::<Coin>("\"AB\"");
            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_non_number_should_give_error() {
            let deserialize_result = serde_json::from_str::<Coin>("\"Crypto.com\"");

            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_plus_prefix_should_work() {
            let deserialize_result = serde_json::from_str::<Coin>("\"+99999\"");

            assert_eq!(
                deserialize_result.expect("Unable to deserialize to Coin"),
                Coin::new(99999).expect("Unable to create new coin")
            );
        }

        #[test]
        fn test_deserialize_from_string_should_work() {
            let deserialize_result = serde_json::from_str::<Coin>("\"99999\"");

            assert_eq!(
                deserialize_result.expect("Unable to deserialize to Coin"),
                Coin::new(99999).expect("Unable to create new coin")
            );
        }

        #[test]
        fn test_deserialize_from_large_amount_should_work() {
            let deserialize_result = serde_json::from_str::<Coin>("\"10000000000000000000\"");

            assert_eq!(
                deserialize_result.expect("Unable to deserialize to Coin"),
                Coin::new(10000000000000000000).expect("Unable to create new coin")
            );
        }
    }
}
