use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;
use std::fmt;
use std::ops::Mul;
use std::prelude::v1::{String, Vec};
use std::str::FromStr;

use crate::common::Timespec;
use crate::init::address::RedeemAddress;
use crate::init::coin::{sum_coins, Coin, CoinError};
use crate::init::MAX_COIN;
use crate::state::account::{StakedState, StakedStateAddress};
use crate::state::tendermint::{TendermintValidatorPubKey, TendermintVotePower};
use crate::state::CouncilNode;
use crate::state::RewardsPoolState;
use crate::tx::fee::{LinearFee, Milli, MilliError};
use std::collections::{BTreeMap, HashSet};

const MAX_SLASH_RATIO: Milli = Milli::new(1, 0); // 1.0

#[derive(Debug, PartialEq, Eq, Clone)]
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
pub enum AccountType {
    // vanilla -- redeemable
    ExternallyOwnedAccount,
    // smart contracts -- non-redeemable (moved to the initial rewards pool)
    Contract,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum StakedStateDestination {
    Bonded,
    UnbondedFromGenesis,
    UnbondedFromCustomTime(Timespec),
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

#[derive(Debug)]
pub enum DistributionError {
    DistributionCoinError(CoinError),
    DoesNotMatchMaxSupply(Coin),
    AddressNotInDistribution(RedeemAddress),
    DoesNotMatchRequiredAmount(RedeemAddress, Coin),
    InvalidValidatorKey,
    DuplicateValidatorKey,
    InvalidValidatorAccount,
    NoValidators,
    InvalidVotingPower,
}

impl fmt::Display for DistributionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DistributionError::DistributionCoinError(c) => c.fmt(f),
            DistributionError::DoesNotMatchMaxSupply(c) => write!(
                f,
                "The total sum of allocated amounts ({}) does not match the expected total supply ({})",
                c,
                MAX_COIN
            ),
            DistributionError::AddressNotInDistribution(a) => {
                write!(f, "Address not found in the distribution ({})", a)
            },
            DistributionError::DoesNotMatchRequiredAmount(a, c) => {
                write!(f, "Address ({}) does not have the expected amount ({}) or is not an externally owned account", a, c)
            },
            DistributionError::InvalidValidatorKey => {
                write!(f, "Invalid validator key")
            },
            DistributionError::InvalidValidatorAccount => {
                write!(f, "Invalid validator account")
            },
            DistributionError::DuplicateValidatorKey => {
                write!(f, "Duplicate validator key")
            },
            DistributionError::NoValidators => {
                write!(f, "No validators / council nodes specified")
            },
            DistributionError::InvalidVotingPower => {
                write!(f, "Invalid voting power")
            },
        }
    }
}

impl InitConfig {
    /// creates a new config (mainly for testing / tools)
    pub fn new(
        rewards_pool: Coin,
        owners: BTreeMap<RedeemAddress, (StakedStateDestination, Coin)>,
        network_params: InitNetworkParameters,
        council_nodes: BTreeMap<RedeemAddress, ValidatorPubkey>,
    ) -> Self {
        InitConfig {
            rewards_pool,
            distribution: owners,
            network_params,
            council_nodes,
        }
    }

    fn check_validator_address(&self, address: &RedeemAddress) -> Result<(), DistributionError> {
        let expected = self.network_params.required_council_node_stake;
        match self.distribution.get(address) {
            Some((d, c)) if *d == StakedStateDestination::Bonded && *c == expected => Ok(()),
            Some((_, c)) => Err(DistributionError::DoesNotMatchRequiredAmount(*address, *c)),
            None => Err(DistributionError::AddressNotInDistribution(*address)),
        }
    }

    fn check_validator_key(
        &self,
        pubkey: &ValidatorPubkey,
    ) -> Result<TendermintValidatorPubKey, DistributionError> {
        if let Ok(key) = base64::decode(&pubkey.consensus_pubkey_b64) {
            let key_len = key.len();
            match (key_len, &pubkey.consensus_pubkey_type) {
                (32, ValidatorKeyType::Ed25519) => {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&key);
                    Ok(TendermintValidatorPubKey::Ed25519(out))
                }
                _ => Err(DistributionError::InvalidValidatorKey),
            }
        } else {
            Err(DistributionError::InvalidValidatorKey)
        }
    }

    /// returns the initial accounts
    /// assumes one called [validate_config_get_genesis], otherwise it may panic
    fn get_account(&self, genesis_time: Timespec) -> Vec<StakedState> {
        self.distribution
            .iter()
            .map(|(address, (destination, amount))| {
                let bonded = match destination {
                    StakedStateDestination::Bonded => true,
                    StakedStateDestination::UnbondedFromGenesis => false,
                    StakedStateDestination::UnbondedFromCustomTime(_time) => false,
                };
                // TODO: change the define of `new_init` and use StakedStateDestination directly
                StakedState::new_init(
                    *amount,
                    genesis_time,
                    StakedStateAddress::BasicRedeem(*address),
                    bonded,
                )
            })
            .collect()
    }

    /// checks if the config is valid:
    /// - initial validator configuration is correct
    /// - the total amount doesn't go over the maximum supply
    /// - ...
    /// if valid, it'll return the genesis "state"
    pub fn validate_config_get_genesis(
        &self,
        genesis_time: Timespec,
    ) -> Result<(Vec<StakedState>, RewardsPoolState, Vec<CouncilNode>), DistributionError> {
        if self.council_nodes.is_empty() {
            return Err(DistributionError::NoValidators);
        }
        // check validator pubkey is duplicated or not
        let pub_keys: HashSet<String> = self
            .council_nodes
            .iter()
            .map(|(_, pubkey)| pubkey.consensus_pubkey_b64.clone())
            .collect();
        if pub_keys.len() != self.council_nodes.len() {
            return Err(DistributionError::DuplicateValidatorKey);
        }

        let validators: Result<Vec<CouncilNode>, DistributionError> = self
            .council_nodes
            .iter()
            .map(|(address, pubkey)| {
                self.check_validator_address(address)?;
                let validator_key = self.check_validator_key(pubkey)?;
                Ok(CouncilNode::new(
                    StakedStateAddress::BasicRedeem(*address),
                    validator_key,
                ))
            })
            .collect();
        Coin::new(
            u64::from(self.network_params.required_council_node_stake)
                * self.council_nodes.len() as u64,
        )
        .map(TendermintVotePower::from) // sanity check
        .map_err(|_| DistributionError::InvalidVotingPower)?;

        // check the total amount
        match sum_coins(self.distribution.iter().map(|(_, (_, amount))| *amount)) {
            Ok(s) => {
                let sum_result = s + self.rewards_pool;
                match sum_result {
                    Ok(sum) => {
                        if sum != Coin::max() {
                            return Err(DistributionError::DoesNotMatchMaxSupply(sum));
                        }
                    }
                    Err(e) => {
                        return Err(DistributionError::DistributionCoinError(e));
                    }
                }
            }
            Err(e) => {
                return Err(DistributionError::DistributionCoinError(e));
            }
        }

        let accounts = self.get_account(genesis_time);
        let rewards_pool = RewardsPoolState::new(self.rewards_pool, 0);
        Ok((accounts, rewards_pool, validators?))
    }
}
