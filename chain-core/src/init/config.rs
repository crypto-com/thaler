use crate::common::Timespec;
use crate::init::address::RedeemAddress;
use crate::init::coin::{sum_coins, Coin, CoinError};
pub use crate::init::params::*;
use crate::init::MAX_COIN;
use crate::state::account::{StakedState, StakedStateAddress, StakedStateDestination};
use crate::state::tendermint::{TendermintValidatorPubKey, TendermintVotePower};
use crate::state::CouncilNode;
use crate::state::RewardsPoolState;
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
                StakedState::new_init(
                    *amount,
                    Some(genesis_time),
                    StakedStateAddress::BasicRedeem(*address),
                    destination,
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
