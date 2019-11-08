use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::fmt;
use std::prelude::v1::{String, ToString, Vec};

/// Tendermint block height
/// TODO: u64?
pub type BlockHeight = i64;

/// The protobuf structure currently has "String" to denote the type / length
/// and variable length byte array. In this internal representation,
/// it's desirable to keep it restricted and compact. (TM should be encoding using the compressed form.)
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TendermintValidatorPubKey {
    Ed25519([u8; 32]),
    // there's PubKeySecp256k1, but https://tendermint.com/docs/spec/abci/apps.html#validator-updates
    // "The pub_key currently supports only one type:"
    // "type = "ed25519" anddata = <raw 32-byte public key>`"
    // there's also PubKeyMultisigThreshold, but that probably wouldn't be used for individual nodes / validators
    // TODO: some other schemes when they are added in TM?
}

impl TendermintValidatorPubKey {
    pub fn to_validator_update(&self) -> (String, Vec<u8>) {
        match self {
            TendermintValidatorPubKey::Ed25519(key) => {
                let mut v = Vec::with_capacity(32);
                v.extend_from_slice(&key[..]);
                ("ed25519".to_string(), v)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Encode, Decode)]
pub struct TendermintValidatorAddress([u8; 20]);

impl From<&TendermintValidatorAddress> for [u8; 20] {
    #[inline]
    fn from(address: &TendermintValidatorAddress) -> [u8; 20] {
        address.0
    }
}

#[cfg(all(feature = "serde", feature = "hex"))]
impl Serialize for TendermintValidatorAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

#[cfg(all(feature = "serde", feature = "hex"))]
impl<'de> Deserialize<'de> for TendermintValidatorAddress {
    fn deserialize<D>(deserializer: D) -> Result<TendermintValidatorAddress, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TendermintAddressVisitor;

        impl<'de> Visitor<'de> for TendermintAddressVisitor {
            type Value = TendermintValidatorAddress;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("hex encoded tendermint validator address")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let address_bytes = hex::decode(s).map_err(de::Error::custom)?;
                TendermintValidatorAddress::try_from(address_bytes.as_slice())
                    .map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(TendermintAddressVisitor)
    }
}

#[cfg(feature = "hex")]
impl fmt::Display for TendermintValidatorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<&TendermintValidatorPubKey> for TendermintValidatorAddress {
    fn from(pub_key: &TendermintValidatorPubKey) -> TendermintValidatorAddress {
        let mut hasher = Sha256::new();

        match pub_key {
            TendermintValidatorPubKey::Ed25519(ref pub_key) => hasher.input(pub_key),
        }

        let mut hash = hasher.result().to_vec();
        hash.truncate(20);

        let mut address_bytes = [0; 20];
        address_bytes.copy_from_slice(&hash);

        TendermintValidatorAddress(address_bytes)
    }
}

impl From<TendermintValidatorPubKey> for TendermintValidatorAddress {
    #[inline]
    fn from(pub_key: TendermintValidatorPubKey) -> TendermintValidatorAddress {
        TendermintValidatorAddress::from(&pub_key)
    }
}

/// Error while converting bytes to tendermint address
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum TendermintValidatorAddressError {
    /// Provided address is longer than 20 bytes
    Long,
    /// Provided address is shorter than 20 bytes
    Short,
}

impl fmt::Display for TendermintValidatorAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TendermintValidatorAddressError::Long => {
                write!(f, "Provided address is longer than 20 bytes")
            }
            TendermintValidatorAddressError::Short => {
                write!(f, "Provided address is shorter than 20 bytes")
            }
        }
    }
}

impl ::std::error::Error for TendermintValidatorAddressError {}

impl TryFrom<&[u8]> for TendermintValidatorAddress {
    type Error = TendermintValidatorAddressError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let length = bytes.len();

        if length == 20 {
            let mut address_bytes = [0; 20];
            address_bytes.copy_from_slice(bytes);
            Ok(Self(address_bytes))
        } else if length < 20 {
            Err(TendermintValidatorAddressError::Short)
        } else {
            Err(TendermintValidatorAddressError::Long)
        }
    }
}

/// "Note that the maximum total power of the validator set is bounded by MaxTotalVotingPower = MaxInt64 / 1000.
/// 1000 is chosen because we want to be able to do fixed point arithmetic operations on `TendermintVotePower` using `Milli`.
/// Applications are responsible for ensuring they do not make changes to the validator set that cause it to exceed this limit."
pub const TENDERMINT_MAX_VOTE_POWER: i64 = std::i64::MAX / 1000;

/// Tendermint consensus voting power
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TendermintVotePower(i64);

impl From<TendermintVotePower> for i64 {
    fn from(c: TendermintVotePower) -> i64 {
        c.0
    }
}

/// error type relating to `TendermintVotePower` operations
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum TendermintVotePowerError {
    /// means that the given value was out of bound
    ///
    /// Min bound being: 0, Max bound being: `TENDERMINT_MAX_VOTE_POWER`.
    OutOfBound(i64),

    Negative,
}

impl fmt::Display for TendermintVotePowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TendermintVotePowerError::OutOfBound(ref v) => write!(
                f,
                "Voting power of value {} is out of bound. Min voting power: 0, Max voting power value: {}.",
                v, TENDERMINT_MAX_VOTE_POWER
            ),
            TendermintVotePowerError::Negative => write!(f, "Voting power cannot hold a negative value"),
        }
    }
}

impl ::std::error::Error for TendermintVotePowerError {}

type TendermintVotePowerResult = Result<TendermintVotePower, TendermintVotePowerError>;

impl TendermintVotePower {
    /// create a voting power of the given value
    pub fn new(v: i64) -> TendermintVotePowerResult {
        // specs: "power must be non-negative"
        // protobuf defs use signed integer for some reason
        if v < 0 {
            return Err(TendermintVotePowerError::Negative);
        }
        if v > TENDERMINT_MAX_VOTE_POWER {
            return Err(TendermintVotePowerError::OutOfBound(v));
        }
        Ok(TendermintVotePower(v))
    }

    /// create a voting power of value `0` / disabled / jailed validator
    pub fn zero() -> Self {
        TendermintVotePower(0)
    }
}
