//! # Eth-style Account address (20 bytes)
//! adapted from https://github.com/ETCDEVTeam/emerald-rs (Emerald Vault)
//! Copyright (c) 2018, ETCDEV (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2018 - 2019, Foris Limited (licensed under the Apache License, Version 2.0)
//!
//! ### Generating Address
//! There are three main steps to obtain chain address from public keys
//! - Start with the public key. (64 bytes)
//! - Take a Keccak-256 hash of public key. (Note: Keccak-256 is different from SHA3-256. [Difference between Keccak256 and SHA3-256](https://ethereum.stackexchange.com/questions/30369/difference-between-keccak256-and-sha3) ) (32 bytes)
//! - Take the last 20 bytes of this Keccak-256 hash. Or, in other words, drop the first 12 bytes.
//!   These 20 bytes are the address.
//!
//! [Recommended Read](https://kobl.one/blog/create-full-ethereum-keypair-and-address/)
use bech32::{self, u5, FromBase32, ToBase32};
use parity_codec::{Decode, Encode};
use std::prelude::v1::{String, ToString};
use std::str::FromStr;
use std::{fmt, ops};

use hex;
use secp256k1::key::PublicKey;
#[cfg(feature = "serde")]
use serde::de::Error;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tiny_keccak::Keccak;

use crate::common::{H256, HASH_SIZE_256};

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CroAddressError {
    Bech32Error(String),
    ConvertError,
}

#[cfg(not(any(feature = "mesalock_sgx", target_env = "sgx")))]
impl ::std::error::Error for CroAddressError {}

// CRMS: mainnet staked-state
// CRMT: mainnet transfer
// CRTS: testnet staked-state
// CRTT: testnet transfer
pub trait CroAddress<T> {
    fn to_cro(&self) -> Result<String, CroAddressError>;
    fn from_cro(encoded: &str) -> Result<T, CroAddressError>;
    fn to_hex(&self) -> Result<String, CroAddressError>;
    fn from_hex(encoded: &str) -> Result<T, CroAddressError>;
}

/// Keccak-256 crypto hash length in bytes
pub const KECCAK256_BYTES: usize = 32;

/// Calculate Keccak-256 crypto hash
pub fn keccak256(data: &[u8]) -> H256 {
    let mut output = [0u8; HASH_SIZE_256];
    Keccak::keccak256(data, &mut output);
    output
}

/// Convert a slice into array
///
/// # Arguments
///
/// * `slice` - slice to be converted
///
pub fn to_arr<A, T>(slice: &[T]) -> A
where
    A: AsMut<[T]> + Default,
    T: Clone,
{
    let mut arr = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut arr).clone_from_slice(slice);
    arr
}

/// Core domain logic errors
#[derive(Debug)]
pub enum ErrorAddress {
    /// An invalid length
    InvalidLength(usize),

    /// An unexpected hexadecimal prefix (should be '0x')
    InvalidHexLength(String),

    /// An unexpected hexadecimal encoding
    UnexpectedHexEncoding(hex::FromHexError),

    /// ECDSA crypto error
    EcdsaCrypto(secp256k1::Error),

    /// CRO error
    InvalidCroAddress,
}

impl From<hex::FromHexError> for ErrorAddress {
    fn from(err: hex::FromHexError) -> Self {
        ErrorAddress::UnexpectedHexEncoding(err)
    }
}

impl From<secp256k1::Error> for ErrorAddress {
    fn from(err: secp256k1::Error) -> Self {
        ErrorAddress::EcdsaCrypto(err)
    }
}

impl fmt::Display for ErrorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ErrorAddress::InvalidLength(len) => write!(f, "Invalid length: {}", len),
            ErrorAddress::InvalidHexLength(ref str) => {
                write!(f, "Invalid hex data length: {}", str)
            }
            ErrorAddress::UnexpectedHexEncoding(ref err) => {
                write!(f, "Unexpected hexadecimal encoding: {}", err)
            }
            ErrorAddress::EcdsaCrypto(ref err) => write!(f, "ECDSA crypto error: {}", err),
            ErrorAddress::InvalidCroAddress => write!(f, "Invalid CroAddress"),
        }
    }
}

impl fmt::Display for CroAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CroAddressError::Bech32Error(e) => write!(f, "CroAddressError Bech32Error: {}", e),
            CroAddressError::ConvertError => write!(f, "CroAddressError ConvertError"),
        }
    }
}

#[cfg(not(any(feature = "mesalock_sgx", target_env = "sgx")))]
impl std::error::Error for ErrorAddress {
    fn description(&self) -> &str {
        "Core error"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            ErrorAddress::UnexpectedHexEncoding(ref err) => Some(err),
            ErrorAddress::EcdsaCrypto(ref err) => Some(err),
            _ => None,
        }
    }
}

/// Fixed bytes number to represent `RedeemAddress` (Eth-style)
pub const REDEEM_ADDRESS_BYTES: usize = 20;

pub type RedeemAddressRaw = [u8; REDEEM_ADDRESS_BYTES];

/// Eth-style Account address (20 bytes)
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct RedeemAddress(pub RedeemAddressRaw);

impl RedeemAddress {
    /// Try to convert a byte vector to `RedeemAddress`.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice with `REDEEM_ADDRESS_BYTES` length
    ///
    pub fn try_from(data: &[u8]) -> Result<Self, ErrorAddress> {
        if data.len() != REDEEM_ADDRESS_BYTES {
            return Err(ErrorAddress::InvalidLength(data.len()));
        }

        Ok(RedeemAddress(to_arr(data)))
    }
}

impl CroAddress<RedeemAddress> for RedeemAddress {
    fn to_cro(&self) -> Result<String, CroAddressError> {
        let checked_data: Vec<u5> = self.0.to_vec().to_base32();
        match super::CURRENT_NETWORK {
            super::network::Network::Testnet => {
                let encoded = bech32::encode("crts", checked_data).expect("bech32 crms encoding");
                Ok(encoded.to_string())
            }
            super::network::Network::Mainnet => {
                let encoded = bech32::encode("crms", checked_data).expect("bech32 crms encoding");
                Ok(encoded.to_string())
            }
        }
    }

    fn from_cro(encoded: &str) -> Result<Self, CroAddressError> {
        bech32::decode(encoded)
            .map_err(|e| CroAddressError::Bech32Error(e.to_string()))
            .and_then(|a| Vec::from_base32(&a.1).map_err(|_e| CroAddressError::ConvertError))
            .and_then(|a| {
                RedeemAddress::try_from(&a.as_slice()).map_err(|_e| CroAddressError::ConvertError)
            })
    }

    fn from_hex(s: &str) -> Result<Self, CroAddressError> {
        if s.len() != REDEEM_ADDRESS_BYTES * 2 && !s.starts_with("0x") {
            return Err(CroAddressError::ConvertError);
        }

        let value = if s.starts_with("0x") {
            s.split_at(2).1
        } else {
            s
        };
        hex::decode(&value)
            .map_err(|_e| CroAddressError::ConvertError)
            .and_then(|a| {
                println!("try from {} length={}", hex::encode(&a), a.len());
                let a = RedeemAddress::try_from(&a.as_slice())
                    .map_err(|_e| CroAddressError::ConvertError);
                println!("result={:?}", a);
                a
            })
    }

    fn to_hex(&self) -> Result<String, CroAddressError> {
        Ok(format!("0x{}", hex::encode(self.0)))
    }
}
impl ops::Deref for RedeemAddress {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&PublicKey> for RedeemAddress {
    fn from(pk: &PublicKey) -> Self {
        let hash = keccak256(&pk.serialize_uncompressed()[1..]);
        RedeemAddress(to_arr(&hash[12..]))
    }
}

impl From<[u8; REDEEM_ADDRESS_BYTES]> for RedeemAddress {
    fn from(bytes: [u8; REDEEM_ADDRESS_BYTES]) -> Self {
        RedeemAddress(bytes)
    }
}

impl FromStr for RedeemAddress {
    type Err = ErrorAddress;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RedeemAddress::from_hex(s).map_err(|_e| ErrorAddress::InvalidCroAddress)
    }
}

impl fmt::Display for RedeemAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex().unwrap())
    }
}

#[cfg(feature = "serde")]
impl Serialize for RedeemAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for RedeemAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ad = RedeemAddress::from_str(&String::deserialize(deserializer)?);
        match ad {
            Ok(x) => Ok(x),
            Err(e) => Err(D::Error::custom(format!(
                "problem deserializing redeem address: {}",
                e
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_display_zero_address() {
        assert_eq!(
            RedeemAddress::default().to_string(),
            "0x0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn should_display_real_address() {
        let addr = RedeemAddress([
            0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80, 0x89,
            0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
        ]);

        assert_eq!(
            addr.to_string(),
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
        );
    }

    #[test]
    fn should_parse_real_address() {
        let addr = RedeemAddress([
            0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80, 0x89,
            0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
        ]);

        assert_eq!(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse::<RedeemAddress>()
                .unwrap(),
            addr
        );
    }

    #[test]
    fn should_parse_real_address_without_prefix() {
        let addr = RedeemAddress([
            0x0e, 0x7c, 0x04, 0x51, 0x10, 0xb8, 0xdb, 0xf2, 0x97, 0x65, 0x04, 0x73, 0x80, 0x89,
            0x89, 0x19, 0xc5, 0xcb, 0x56, 0xf4,
        ]);

        assert_eq!(
            "0x0e7c045110b8dbf29765047380898919c5cb56f4"
                .parse::<RedeemAddress>()
                .unwrap(),
            addr
        );
    }

    #[test]
    fn should_catch_wrong_address_encoding() {
        assert!("0x___c045110b8dbf29765047380898919c5cb56f4"
            .parse::<RedeemAddress>()
            .is_err());
    }

    #[test]
    fn should_catch_wrong_address_insufficient_length() {
        assert!("0x0e7c045110b8dbf297650473808989"
            .parse::<RedeemAddress>()
            .is_err());
    }

    #[test]
    fn should_catch_wrong_address_excess_length() {
        assert!("0x0e7c045110b8dbf29765047380898919c5cb56f400000000"
            .parse::<RedeemAddress>()
            .is_err());
    }

    #[test]
    fn should_catch_wrong_address_prefix() {
        assert!("0_0e7c045110b8dbf29765047380898919c5cb56f4"
            .parse::<RedeemAddress>()
            .is_err());
    }

    #[test]
    fn should_catch_missing_address_prefix() {
        assert!("_".parse::<RedeemAddress>().is_err());
    }

    #[test]
    fn should_catch_empty_address_string() {
        assert!("".parse::<RedeemAddress>().is_err());
    }

    #[test]
    fn should_be_correct_textual_address() {
        let a = RedeemAddress::from_hex("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap();
        let b = a.to_cro().unwrap();
        assert_eq!(b.to_string(), "crms1pe7qg5gshrdl99m9q3ecpzvfr8zuk4h5jgt0gj");
        let c = RedeemAddress::from_cro(&b).unwrap();
        assert_eq!(c, a);
    }

    #[test]
    fn shoule_be_correct_hex_address() {
        let a = RedeemAddress::from_hex("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap();

        let b = RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap();
        assert_eq!(a, b);
    }
}
