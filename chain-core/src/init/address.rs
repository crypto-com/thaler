//! # Eth-style Account address (20 bytes)
//! adapted from https://github.com/ETCDEVTeam/emerald-rs (Emerald Vault)
//! Copyright (c) 2018, ETCDEV (licensed under the Apache License, Version 2.0)
//! Modifications Copyright (c) 2018 - 2020, Foris Limited (licensed under the Apache License, Version 2.0)
//!
//! ### Generating Address
//! There are three main steps to obtain chain address from public keys
//! - Start with the public key. (64 bytes)
//! - Take a Keccak-256 hash of public key. (Note: Keccak-256 is different from SHA3-256. [Difference between Keccak256 and SHA3-256](https://ethereum.stackexchange.com/questions/30369/difference-between-keccak256-and-sha3) ) (32 bytes)
//! - Take the last 20 bytes of this Keccak-256 hash. Or, in other words, drop the first 12 bytes.
//!   These 20 bytes are the address.
//!
//! [Recommended Read](https://kobl.one/blog/create-full-ethereum-keypair-and-address/)
#[cfg(not(feature = "mesalock_sgx"))]
use bech32::{self, u5, FromBase32, ToBase32};
use parity_scale_codec::{Decode, Encode};
use std::ops;
use std::prelude::v1::String;
#[cfg(not(feature = "mesalock_sgx"))]
use std::str::FromStr;

use secp256k1::key::PublicKey;
#[cfg(not(feature = "mesalock_sgx"))]
use serde::de::Error;
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(not(feature = "mesalock_sgx"))]
use std::fmt;
use tiny_keccak::{Hasher, Keccak};

use crate::common::{H256, HASH_SIZE_256};
#[cfg(not(feature = "mesalock_sgx"))]
use crate::init::network::{get_bech32_human_part_from_network, Network};

#[derive(Debug, PartialEq)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub enum CroAddressError {
    // TODO: use directly bech32::Error or wrap it
    Bech32Error(String),
    InvalidNetwork,
    ConvertError,
}

#[cfg(not(feature = "mesalock_sgx"))]
impl ::std::error::Error for CroAddressError {}

// CRO: mainnet transfer
// TCRO: testnet transfer
// DCRO: devnet/regnet transfer
#[cfg(not(feature = "mesalock_sgx"))]
pub trait CroAddress<T> {
    fn to_cro(&self, network: Network) -> Result<String, CroAddressError>;
    fn from_cro(encoded: &str, network: Network) -> Result<T, CroAddressError>;
}

/// Keccak-256 crypto hash length in bytes
pub const KECCAK256_BYTES: usize = 32;

/// Calculate Keccak-256 crypto hash
pub fn keccak256(data: &[u8]) -> H256 {
    let mut output = [0u8; HASH_SIZE_256];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut output);
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
#[cfg(not(feature = "mesalock_sgx"))]
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

#[cfg(not(feature = "mesalock_sgx"))]
impl From<hex::FromHexError> for ErrorAddress {
    fn from(err: hex::FromHexError) -> Self {
        ErrorAddress::UnexpectedHexEncoding(err)
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl From<secp256k1::Error> for ErrorAddress {
    fn from(err: secp256k1::Error) -> Self {
        ErrorAddress::EcdsaCrypto(err)
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
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

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for CroAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CroAddressError::Bech32Error(e) => write!(f, "CroAddressError Bech32Error: {}", e),
            CroAddressError::ConvertError => write!(f, "CroAddressError ConvertError"),
            CroAddressError::InvalidNetwork => write!(f, "Address belonging to different network"),
        }
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
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
#[derive(Clone, Copy, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[cfg_attr(feature = "mesalock_sgx", derive(Debug))]
pub struct RedeemAddress(pub RedeemAddressRaw);

#[cfg(not(feature = "mesalock_sgx"))]
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

#[cfg(not(feature = "mesalock_sgx"))]
impl CroAddress<RedeemAddress> for RedeemAddress {
    fn to_cro(&self, network: Network) -> Result<String, CroAddressError> {
        let checked_data: Vec<u5> = self.0.to_vec().to_base32();
        let encoded = bech32::encode(get_bech32_human_part_from_network(network), checked_data)
            .expect("bech32 encoding error");
        Ok(encoded)
    }

    fn from_cro(encoded: &str, network: Network) -> Result<Self, CroAddressError> {
        let (human_part, u5_bytes) =
            bech32::decode(encoded).map_err(|e| CroAddressError::Bech32Error(e.to_string()))?;

        if human_part != get_bech32_human_part_from_network(network) {
            return Err(CroAddressError::InvalidNetwork);
        }

        let bytes = Vec::from_base32(&u5_bytes).map_err(|_| CroAddressError::ConvertError)?;

        RedeemAddress::try_from(&bytes).map_err(|_| CroAddressError::ConvertError)
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

#[cfg(not(feature = "mesalock_sgx"))]
impl FromStr for RedeemAddress {
    type Err = ErrorAddress;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != REDEEM_ADDRESS_BYTES * 2 && !s.starts_with("0x") {
            return Err(ErrorAddress::InvalidHexLength(s.to_string()));
        }

        let value = if s.starts_with("0x") {
            s.split_at(2).1
        } else {
            s
        };

        RedeemAddress::try_from(hex::decode(&value)?.as_slice())
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for RedeemAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Debug for RedeemAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(0x{}", hex::encode(self.0))
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl Serialize for RedeemAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
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
        let network = Network::Devnet;

        let redeem_address =
            RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap();
        let bech32_address = redeem_address.to_cro(network).unwrap();
        assert_eq!(
            bech32_address.to_string(),
            "dcro1pe7qg5gshrdl99m9q3ecpzvfr8zuk4h5rm547c"
        );

        let restored_redeem_address = RedeemAddress::from_cro(&bech32_address, network).unwrap();
        assert_eq!(redeem_address, restored_redeem_address);
    }
}
