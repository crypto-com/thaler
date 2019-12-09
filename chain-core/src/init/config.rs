use crate::common::Timespec;
use crate::init::address::RedeemAddress;
use crate::init::coin::{sum_coins, Coin, CoinError};
pub use crate::init::params::*;
use crate::init::MAX_COIN;
use crate::state::account::{
    CouncilNode, StakedState, StakedStateAddress, StakedStateDestination, ValidatorName,
    ValidatorSecurityContact,
};
use crate::state::tendermint::{TendermintValidatorPubKey, TendermintVotePower};
use crate::state::RewardsPoolState;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

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
    InvalidPunishmentConfiguration,
    InvalidRewardsParamter(&'static str),
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
            DistributionError::InvalidPunishmentConfiguration => {
                write!(f, "Invalid punishment configuration (maybe slash_wait_period >= jail_duration)")
            }
            DistributionError::InvalidRewardsParamter(err) => {
                write!(f, "Invalid rewards parameters: {}", err)
            }
        }
    }
}

/// Initial configuration ("app_state" in genesis.json of Tendermint config)
/// TODO: reward/treasury config, extra validator config...
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitConfig {
    // Redeem mapping of ERC20 snapshot: Eth address => (StakedStateDestination,CRO tokens)
    // (doesn't include the rewards pool amount)
    pub distribution: BTreeMap<RedeemAddress, (StakedStateDestination, Coin)>,
    // initial network parameters
    pub network_params: InitNetworkParameters,
    // initial validators
    pub council_nodes: BTreeMap<
        RedeemAddress,
        (
            ValidatorName,
            ValidatorSecurityContact,
            TendermintValidatorPubKey,
        ),
    >,
}

pub type GenesisState = (
    Vec<StakedState>,
    RewardsPoolState,
    Vec<(StakedStateAddress, CouncilNode)>,
);

impl InitConfig {
    /// creates a new config (mainly for testing / tools)
    pub fn new(
        owners: BTreeMap<RedeemAddress, (StakedStateDestination, Coin)>,
        network_params: InitNetworkParameters,
        council_nodes: BTreeMap<
            RedeemAddress,
            (
                ValidatorName,
                ValidatorSecurityContact,
                TendermintValidatorPubKey,
            ),
        >,
    ) -> Self {
        InitConfig {
            distribution: owners,
            network_params,
            council_nodes,
        }
    }

    fn check_validator_address(&self, address: &RedeemAddress) -> Result<(), DistributionError> {
        let expected = self.network_params.required_council_node_stake;
        match self.distribution.get(address) {
            Some((d, c)) if *d == StakedStateDestination::Bonded && *c >= expected => Ok(()),
            Some((_, c)) => Err(DistributionError::DoesNotMatchRequiredAmount(*address, *c)),
            None => Err(DistributionError::AddressNotInDistribution(*address)),
        }
    }

    /// returns the initial accounts
    /// assumes one called [validate_config_get_genesis], otherwise it may panic
    fn get_account(&self, genesis_time: Timespec) -> Vec<StakedState> {
        self.distribution
            .iter()
            .map(|(address, (destination, amount))| match destination {
                StakedStateDestination::Bonded => {
                    let council_node = self.get_council_node(address);
                    StakedState::new_init_bonded(
                        *amount,
                        genesis_time,
                        StakedStateAddress::BasicRedeem(*address),
                        council_node.ok(),
                    )
                }
                StakedStateDestination::UnbondedFromGenesis => StakedState::new_init_unbonded(
                    *amount,
                    genesis_time,
                    StakedStateAddress::BasicRedeem(*address),
                ),
                StakedStateDestination::UnbondedFromCustomTime(time) => {
                    StakedState::new_init_unbonded(
                        *amount,
                        *time,
                        StakedStateAddress::BasicRedeem(*address),
                    )
                }
            })
            .collect()
    }

    fn get_council_node(&self, address: &RedeemAddress) -> Result<CouncilNode, DistributionError> {
        self.check_validator_address(address)?;
        let (name, security_contact, pubkey) = self
            .council_nodes
            .get(address)
            .ok_or(DistributionError::InvalidValidatorAccount)?;
        Ok(CouncilNode::new_with_details(
            name.clone(),
            security_contact.clone(),
            pubkey.clone(),
        ))
    }

    /// checks if the config is valid:
    /// - initial validator configuration is correct
    /// - the total amount doesn't go over the maximum supply
    /// - ...
    /// if valid, it'll return the genesis "state"
    pub fn validate_config_get_genesis(
        &self,
        genesis_time: Timespec,
    ) -> Result<GenesisState, DistributionError> {
        self.network_params
            .rewards_config
            .validate()
            .map_err(DistributionError::InvalidRewardsParamter)?;
        if self.council_nodes.is_empty() {
            return Err(DistributionError::NoValidators);
        }
        // check validator pubkey is duplicated or not
        let pub_keys: HashSet<_> = self
            .council_nodes
            .iter()
            .map(|(_, details)| details.2.clone())
            .collect();
        if pub_keys.len() != self.council_nodes.len() {
            return Err(DistributionError::DuplicateValidatorKey);
        }

        let validators: Result<Vec<(StakedStateAddress, CouncilNode)>, DistributionError> = self
            .council_nodes
            .keys()
            .map(|address| {
                let council_node = self.get_council_node(address)?;
                Ok((StakedStateAddress::BasicRedeem(*address), council_node))
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
                let sum_result = s + self.network_params.rewards_config.monetary_expansion_cap;
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

        if self.network_params.slashing_config.slash_wait_period
            >= self.network_params.jailing_config.jail_duration
        {
            return Err(DistributionError::InvalidPunishmentConfiguration);
        }

        let accounts = self.get_account(genesis_time);
        let rewards_pool = RewardsPoolState::new(
            genesis_time,
            self.network_params.rewards_config.monetary_expansion_tau,
        );
        Ok((accounts, rewards_pool, validators?))
    }
}
