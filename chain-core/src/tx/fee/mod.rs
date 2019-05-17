//! # Fee calculation and fee algorithms
//! adapted from https://github.com/input-output-hk/rust-cardano (Cardano Rust)
//! Copyright (c) 2018, Input Output HK (licensed under the MIT License)
//! Modifications Copyright (c) 2018 - 2019, Foris Limited (licensed under the Apache License, Version 2.0)

use crate::init::coin::{Coin, CoinError};
use crate::tx::TxAux;
use parity_codec::Encode;
use parity_codec_derive::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::num::ParseIntError;
use std::ops::{Add, Mul};
use std::str::FromStr;
use std::{error, fmt};

/// A fee value that represent either a fee to pay, or a fee paid.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct Fee(Coin);

impl Fee {
    pub fn new(coin: Coin) -> Self {
        Fee(coin)
    }

    pub fn to_coin(self) -> Coin {
        self.0
    }
}

/// Represents a 4 digit fixed decimal
/// TODO: overflow checks in Cargo?
/// [profile.release]
/// overflow-checks = true
#[derive(PartialEq, Eq, PartialOrd, Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
#[serde(transparent)]
pub struct Milli(u64);
impl Milli {
    /// takes the integer part and 4-digit fractional part
    /// and returns the 4-digit fixed decimal number (i.ffff)
    pub fn new(i: u64, f: u64) -> Self {
        Milli(i * 1000 + f % 1000)
    }

    /// takes the integer part
    /// and returns the 4-digit fixed decimal number (i.0000)
    pub fn integral(i: u64) -> Self {
        Milli(i * 1000)
    }

    pub fn to_integral(self) -> u64 {
        // note that we want the ceiling
        if self.0 % 1000 == 0 {
            self.0 / 1000
        } else {
            (self.0 / 1000) + 1
        }
    }

    pub fn to_integral_trunc(self) -> u64 {
        self.0 / 1000
    }

    pub fn as_millis(self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
pub enum MilliError {
    /// An invalid length of parts (should be 2)
    InvalidPartsLength(usize),
    /// Number parsing error
    InvalidInteger(ParseIntError),
}

impl fmt::Display for MilliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            MilliError::InvalidPartsLength(len) => {
                write!(f, "Invalid parts length: {} (2 expected)", len)
            }
            MilliError::InvalidInteger(ref err) => write!(f, "Integer parsing error: {}", err),
        }
    }
}

impl From<ParseIntError> for MilliError {
    fn from(err: ParseIntError) -> Self {
        MilliError::InvalidInteger(err)
    }
}

impl FromStr for Milli {
    type Err = MilliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('.').collect::<Vec<&str>>();
        let len = parts.len();
        if len != 2 {
            return Err(MilliError::InvalidPartsLength(len));
        }
        let integral: u64 = parts[0].parse()?;
        let fractional: u64 = parts[1].parse()?;
        Ok(Milli::new(integral, fractional))
    }
}

impl error::Error for MilliError {
    fn description(&self) -> &str {
        "Milli parsing error"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            MilliError::InvalidInteger(ref err) => Some(err),
            _ => None,
        }
    }
}

impl Add for Milli {
    type Output = Milli;
    fn add(self, other: Self) -> Self {
        Milli(self.0 + other.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Mul for Milli {
    type Output = Milli;

    fn mul(self, other: Self) -> Self {
        let v = u128::from(self.0) * u128::from(other.0);
        Milli((v / 1000) as u64)
    }
}

/// Linear fee using the basic affine formula `COEFFICIENT * scale_bytes(txaux).len() + CONSTANT`
#[derive(PartialEq, Eq, PartialOrd, Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode)]
pub struct LinearFee {
    /// this is the minimal fee
    pub constant: Milli,
    /// the transaction's size coefficient fee
    pub coefficient: Milli,
}

impl LinearFee {
    pub fn new(constant: Milli, coefficient: Milli) -> Self {
        LinearFee {
            constant,
            coefficient,
        }
    }

    pub fn estimate(&self, sz: usize) -> Result<Fee, CoinError> {
        let msz = Milli::integral(sz as u64);
        let fee = self.constant + self.coefficient * msz;
        let coin = Coin::new(fee.to_integral())?;
        Ok(Fee(coin))
    }
}

/// Calculation of fees for a specific chosen algorithm
pub trait FeeAlgorithm: Send + Sync {
    fn calculate_fee(&self, num_bytes: usize) -> Result<Fee, CoinError>;
    fn calculate_for_txaux(&self, txaux: &TxAux) -> Result<Fee, CoinError>;
}

impl FeeAlgorithm for LinearFee {
    fn calculate_fee(&self, num_bytes: usize) -> Result<Fee, CoinError> {
        self.estimate(num_bytes)
    }

    fn calculate_for_txaux(&self, txaux: &TxAux) -> Result<Fee, CoinError> {
        self.estimate(txaux.encode().len())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_milli_add_eq(v1: u64, v2: u64) {
        let v = v1 + v2;
        let n1 = Milli::new(v1 / 1000, v1 % 1000);
        let n2 = Milli::new(v2 / 1000, v2 % 1000);
        let n = n1 + n2;
        assert_eq!(v / 1000, n.to_integral_trunc());
    }

    fn test_milli_mul_eq(v1: u64, v2: u64) {
        let v = v1 as u128 * v2 as u128;
        let n1 = Milli::new(v1 / 1000, v1 % 1000);
        let n2 = Milli::new(v2 / 1000, v2 % 1000);
        let n = n1 * n2;
        assert_eq!((v / 1000000) as u64, n.to_integral_trunc());
    }

    #[test]
    fn check_fee_add() {
        test_milli_add_eq(10124128_192, 802_504);
        test_milli_add_eq(1124128_915, 124802_192);
        test_milli_add_eq(241, 900001_901);
        test_milli_add_eq(241, 407);
    }

    #[test]
    fn check_fee_mul() {
        test_milli_mul_eq(10124128_192, 802_192);
        test_milli_mul_eq(1124128_192, 124802_192);
        test_milli_mul_eq(241, 900001_900);
        test_milli_mul_eq(241, 400);
    }
}
