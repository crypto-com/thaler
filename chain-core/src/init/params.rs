use crate::common::Timespec;
use crate::common::{hash256, H256};
use crate::init::address::RedeemAddress;
use crate::init::coin::{Coin, CoinError};
use crate::state::account::StakedStateDestination;
use crate::tx::fee::{Fee, FeeAlgorithm};
use crate::tx::fee::{LinearFee, Milli, MilliError};
use blake2::Blake2s;
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;
use std::ops::Mul;
use std::prelude::v1::String;
use std::str::FromStr;

const MAX_SLASH_RATIO: Milli = Milli::new(1, 0); // 1.0

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitNetworkParameters {
    /// Initial fee setting
    /// -- TODO: perhaps change to be against T: FeeAlgorithm
    /// TBD here, the intention would be to "freeze" the genesis config, so not sure generic field is worth it
    pub initial_fee_policy: LinearFee,
    /// minimal? council node stake
    pub required_council_node_stake: Coin,
    /// stake unbonding time (in seconds)
    pub unbonding_period: u32,
    /// Jailing configuration
    pub jailing_config: JailingParameters,
    /// Slashing configuration
    pub slashing_config: SlashingParameters,
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetworkParameters {
    /// parameters specified at genesis time
    Genesis(InitNetworkParameters),
}

/// TODO: extract these to a trait?
impl NetworkParameters {
    /// retrieves the hash of the current state (currently blake2s(scale_code_bytes(network params)))
    pub fn hash(&self) -> H256 {
        hash256::<Blake2s>(&self.encode())
    }

    pub fn get_required_council_node_stake(&self) -> Coin {
        match self {
            NetworkParameters::Genesis(params) => params.required_council_node_stake,
        }
    }

    pub fn get_byzantine_slash_percent(&self) -> SlashRatio {
        match self {
            NetworkParameters::Genesis(params) => params.slashing_config.byzantine_slash_percent,
        }
    }

    pub fn get_liveness_slash_percent(&self) -> SlashRatio {
        match self {
            NetworkParameters::Genesis(params) => params.slashing_config.liveness_slash_percent,
        }
    }

    pub fn get_jail_duration(&self) -> Timespec {
        match self {
            NetworkParameters::Genesis(params) => {
                Timespec::from(params.jailing_config.jail_duration)
            }
        }
    }

    pub fn get_slash_wait_period(&self) -> Timespec {
        match self {
            NetworkParameters::Genesis(params) => {
                Timespec::from(params.slashing_config.slash_wait_period)
            }
        }
    }

    pub fn get_missed_block_threshold(&self) -> u16 {
        match self {
            NetworkParameters::Genesis(params) => params.jailing_config.missed_block_threshold,
        }
    }

    pub fn get_block_signing_window(&self) -> u16 {
        match self {
            NetworkParameters::Genesis(params) => params.jailing_config.block_signing_window,
        }
    }

    pub fn get_unbonding_period(&self) -> u32 {
        match self {
            NetworkParameters::Genesis(params) => params.unbonding_period,
        }
    }

    pub fn calculate_fee(&self, num_bytes: usize) -> Result<Fee, CoinError> {
        match self {
            NetworkParameters::Genesis(params) => {
                params.initial_fee_policy.calculate_fee(num_bytes)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct JailingParameters {
    /// Minimum jailing time for punished accounts (in seconds)
    pub jail_duration: u32,
    /// Number of blocks for which the moving average is calculated for uptime tracking
    pub block_signing_window: u16,
    /// Maximum number of blocks with faulty/missed validations allowed for an account in last `block_signing_window`
    /// blocks before it gets jailed
    pub missed_block_threshold: u16,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlashingParameters {
    /// Percentage of funds (bonded + unbonded) slashed when validator is not live (liveness is calculated by jailing
    /// parameters)
    pub liveness_slash_percent: SlashRatio,
    /// Percentage of funds (bonded + unbonded) slashed when validator makes a byzantine fault
    pub byzantine_slash_percent: SlashRatio,
    /// Time (in seconds) to wait before slashing funds from an account
    pub slash_wait_period: u32,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy, Encode, Decode)]
pub struct SlashRatio(Milli);

impl SlashRatio {
    #[inline]
    pub(crate) fn as_millis(self) -> u64 {
        self.0.as_millis()
    }
}

impl Mul for SlashRatio {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: SlashRatio) -> Self::Output {
        SlashRatio::try_from(self.0 * rhs.0)
            .expect("Slash ratio is greater than 1.0 after multiplication") // This will never fail because both slash ratios are below 1.0
    }
}

impl TryFrom<Milli> for SlashRatio {
    type Error = SlashRatioError;

    fn try_from(milli: Milli) -> Result<Self, Self::Error> {
        if milli > MAX_SLASH_RATIO {
            Err(SlashRatioError::GreaterThanMax)
        } else {
            Ok(Self(milli))
        }
    }
}

impl FromStr for SlashRatio {
    type Err = SlashRatioError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let milli = Milli::from_str(s).map_err(SlashRatioError::MilliError)?;
        SlashRatio::try_from(milli)
    }
}

impl fmt::Display for SlashRatio {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "serde")]
impl Serialize for SlashRatio {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SlashRatio {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SlashRatioVisitor;

        impl<'de> de::Visitor<'de> for SlashRatioVisitor {
            type Value = SlashRatio;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Slash ratio between 0.0 to 1.0")
            }

            fn visit_str<E>(self, value: &str) -> Result<SlashRatio, E>
            where
                E: de::Error,
            {
                SlashRatio::from_str(value).map_err(|e| de::Error::custom(e.to_string()))
            }
        }

        deserializer.deserialize_str(SlashRatioVisitor)
    }
}

#[derive(Debug)]
pub enum SlashRatioError {
    /// Slashing ratio is greater than maximum allowed (i.e., 1.0)
    GreaterThanMax,
    /// Error while parsing decimal numnber
    MilliError(MilliError),
}

impl fmt::Display for SlashRatioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlashRatioError::GreaterThanMax => {
                write!(f, "Slashing ratio is greater than maximum allowed")
            }
            SlashRatioError::MilliError(e) => {
                write!(f, "Error while parsing decimal number: {}", e)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ValidatorKeyType {
    Ed25519,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ValidatorPubkey {
    // Tendermint consensus public key type
    pub consensus_pubkey_type: ValidatorKeyType,
    // Tendermint consensus public key encoded in base64
    pub consensus_pubkey_b64: String,
}

/// Initial configuration ("app_state" in genesis.json of Tendermint config)
/// TODO: reward/treasury config, extra validator config...
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitConfig {
    // initial rewards pool of CRO tokens
    pub rewards_pool: Coin,
    // Redeem mapping of ERC20 snapshot: Eth address => (StakedStateDestination,CRO tokens)
    // (doesn't include the rewards pool amount)
    pub distribution: BTreeMap<RedeemAddress, (StakedStateDestination, Coin)>,
    // initial network parameters
    pub network_params: InitNetworkParameters,
    // initial validators
    pub council_nodes: BTreeMap<RedeemAddress, ValidatorPubkey>,
}
