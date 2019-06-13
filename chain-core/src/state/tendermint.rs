use parity_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Tendermint block height
/// TODO: u64?
pub type BlockHeight = i64;

/// The protobuf structure currently has "String" to denote the type / length
/// and variable length byte array. In this internal representation,
/// it's desirable to keep it restricted and compact. (TM should be encoding using the compressed form.)
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode)]
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

/// "Note that the maximum total power of the validator set is bounded by MaxTotalVotingPower = MaxInt64 / 8.
/// Applications are responsible for ensuring they do not make changes to the validator set that cause it to exceed this limit."
pub const TENDERMINT_MAX_VOTE_POWER: i64 = std::i64::MAX / 8;

/// Tendermint consensus voting power
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
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
