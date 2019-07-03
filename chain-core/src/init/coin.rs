//! # Value with associated properties (e.g. min/max bounds)
//! adapted from https://github.com/input-output-hk/rust-cardano (Cardano Rust)
//! Copyright (c) 2018, Input Output HK (licensed under the MIT License)
//! Modifications Copyright (c) 2018 - 2019, Foris Limited (licensed under the Apache License, Version 2.0)

use crate::init::{MAX_COIN, MAX_COIN_DECIMALS, MAX_COIN_UNITS};
use crate::state::tendermint::TendermintVotePower;
use crate::state::tendermint::TENDERMINT_MAX_VOTE_POWER;
use parity_codec::{Decode, Encode, Input};

use serde::{Deserialize, Serialize, Serializer};

use serde::de::{Deserializer, Error, Visitor};

use static_assertions::const_assert;
use std::convert::TryFrom;
use std::{fmt, mem, ops, result, slice};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Encode)]
pub struct Coin(u64);

/// error type relating to `Coin` operations
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, serde::Serialize, Deserialize)]
pub enum CoinError {
    /// means that the given value was out of bound
    ///
    /// Max bound being: `MAX_COIN`.
    OutOfBound(u64),

    ParseIntError,

    Negative,
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
        let sum = self.0.checked_add(other.0);
        match sum {
            None => Err(CoinError::OutOfBound(0)),
            Some(v) => Coin::new(v),
        }
    }
}
impl<'a> ops::Add<&'a Coin> for Coin {
    type Output = CoinResult;
    fn add(self, other: &'a Coin) -> Self::Output {
        let sum = self.0.checked_add(other.0);
        match sum {
            None => Err(CoinError::OutOfBound(0)),
            Some(v) => Coin::new(v),
        }
    }
}
impl ops::Sub for Coin {
    type Output = CoinResult;
    fn sub(self, other: Coin) -> Self::Output {
        let sub = self.0.checked_sub(other.0);
        match sub {
            None => Err(CoinError::Negative),
            Some(v) => Coin::new(v),
        }
    }
}
impl<'a> ops::Sub<&'a Coin> for Coin {
    type Output = CoinResult;
    fn sub(self, other: &'a Coin) -> Self::Output {
        let sub = self.0.checked_sub(other.0);
        match sub {
            None => Err(CoinError::Negative),
            Some(v) => Coin::new(v),
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

impl From<Coin> for TendermintVotePower {
    fn from(c: Coin) -> TendermintVotePower {
        const_assert!(std::i64::MAX > MAX_COIN_UNITS);
        const_assert!(TENDERMINT_MAX_VOTE_POWER > MAX_COIN_UNITS);
        // NOTE: conversions below should never panic
        let vote_power = i64::try_from(c.0 / MAX_COIN_DECIMALS)
            .expect("i64::MAX is larger than `MAX_COIN / MAX_COIN_DECIMALS`");
        TendermintVotePower::new(vote_power)
            .expect("TENDERMINT_MAX_VOTE_POWER is larger than `MAX_COIN / MAX_COIN_DECIMALS`")
    }
}

impl From<u32> for Coin {
    fn from(c: u32) -> Coin {
        Coin(u64::from(c))
    }
}

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

    #[test]
    // test whether oveflow error occur
    fn coin_overflow_add_should_produce_error() {
        let a = Coin::max();
        let b = Coin::max();
        let sum = a + b;
        assert!(sum.is_err());
    }

    #[test]
    // test whether overflow error not occur
    fn coin_overflow_add_shoule_be_the_same() {
        let a = Coin::max();
        let b = Coin::new(0).unwrap();
        let sum = (a + b).unwrap();
        assert!(sum == a);
    }

    #[test]
    // test whether underflow error occur
    fn coin_sub_should_produce_error() {
        let a = Coin::new(0).unwrap();
        let b = Coin::max();
        let sub = a - b;
        assert!(sub.is_err());
    }

    #[test]
    // test whether underflow error not occur
    fn coin_underflow_sub_should_be_the_same() {
        let a = Coin::max();
        let b = Coin::new(0).unwrap();
        let sub = (a - b).unwrap();
        assert!(sub == a);
    }

    quickcheck! {

        // test a given u32 is always a valid value for a `Coin`
        fn coin_from_u32_always_valid(v: u32) -> bool {
            Coin::new(v as u64).is_ok()
        }

        // test a comparison works as expected or fails
        fn coin_sum_comparison(a: u64, b: u64, c: u64) -> bool {
            let c_a = Coin::new(a);
            let c_b = Coin::new(b);
            let c_c = Coin::new(c);
            let c_bc = match c_b {
                Ok(coin_b) => {
                    // maybe error
                    c_c.and_then(|coin_c| coin_c + coin_b)
                },
                _ => {
                    // error
                    c_b
                }
            };
            let longer_a = u128::from(a);
            let longer_bc = u128::from(b) + u128::from(c);
            match (c_a, c_bc) {
                (Ok(coin_a), Ok(coin_bc)) => {
                    // they are equal
                    ((longer_a == longer_bc) && (coin_a == coin_bc))
                    // a is smaller
                    || ((longer_a < longer_bc) && (coin_a < coin_bc))
                    // b+c is smaller
                    || ((longer_a > longer_bc) && (coin_a > coin_bc))

                },
                _ => {
                    // either 'a' was too big or 'b+c' was too big
                    true
                }
            }
        }

    }
}
