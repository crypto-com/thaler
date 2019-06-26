#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt;
use std::prelude::v1::{String, Vec};

use crate::common::Timespec;
use crate::init::address::RedeemAddress;
use crate::init::coin::{sum_coins, Coin, CoinError};
use crate::init::MAX_COIN;
use crate::state::account::{StakedState, StakedStateAddress};
use crate::state::tendermint::{TendermintValidatorPubKey, TendermintVotePower};
use crate::state::CouncilNode;
use crate::state::RewardsPoolState;
use crate::tx::fee::LinearFee;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitNetworkParameters {
    // Initial fee setting
    // -- TODO: perhaps change to be against T: FeeAlgorithm
    // TBD here, the intention would be to "freeze" the genesis config, so not sure generic field is worth it
    pub initial_fee_policy: LinearFee,
    // minimal? council node stake
    pub required_council_node_stake: Coin,
    // stake unbonding time (in seconds)
    pub unbonding_period: u32,
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
pub enum ValidatorKeyType {
    Ed25519,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitialValidator {
    // account with the required staked amount
    pub staking_account_address: RedeemAddress,
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
    // Redeem mapping of ERC20 snapshot: Eth address => (CRO tokens, AccountType)
    pub distribution: BTreeMap<RedeemAddress, (Coin, AccountType)>,
    // 0x35f517cab9a37bc31091c2f155d965af84e0bc85 on Eth mainnet ERC20
    pub launch_incentive_from: RedeemAddress,
    // 0x20a0bee429d6907e556205ef9d48ab6fe6a55531 on Eth mainnet ERC20
    pub launch_incentive_to: RedeemAddress,
    // 0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07 on Eth mainnet ERC20
    pub long_term_incentive: RedeemAddress,
    // initial network parameters
    pub network_params: InitNetworkParameters,
    // initial validators
    pub council_nodes: Vec<InitialValidator>,
}

pub enum DistributionError {
    DistributionCoinError(CoinError),
    DoesNotMatchMaxSupply(Coin),
    AddressNotInDistribution(RedeemAddress),
    DoesNotMatchRequiredAmount(RedeemAddress, Coin),
    InvalidValidatorKey,
    DuplicateValidatorKey,
    InvalidValidatorAccount,
    DuplicateValidatorAccount,
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
            DistributionError::DuplicateValidatorAccount => {
                write!(f, "Duplicate validator account")
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
        owners: BTreeMap<RedeemAddress, (Coin, AccountType)>,
        launch_incentive_from: RedeemAddress,
        launch_incentive_to: RedeemAddress,
        long_term_incentive: RedeemAddress,
        network_params: InitNetworkParameters,
        council_nodes: Vec<InitialValidator>,
    ) -> Self {
        InitConfig {
            distribution: owners,
            launch_incentive_from,
            launch_incentive_to,
            long_term_incentive,
            network_params,
            council_nodes,
        }
    }

    fn check_address(&self, address: &RedeemAddress) -> Result<(), DistributionError> {
        if self.distribution.contains_key(address) {
            Ok(())
        } else {
            Err(DistributionError::AddressNotInDistribution(*address))
        }
    }

    fn check_address_expected_amount(
        &self,
        address: &RedeemAddress,
        expected: Coin,
    ) -> Result<(), DistributionError> {
        match self.distribution.get(address) {
            Some((c, t)) if *c == expected && *t == AccountType::ExternallyOwnedAccount => Ok(()),
            Some((c, _)) => Err(DistributionError::DoesNotMatchRequiredAmount(*address, *c)),
            None => Err(DistributionError::AddressNotInDistribution(*address)),
        }
    }

    fn check_validator_key(
        t: &ValidatorKeyType,
        encoded: &str,
    ) -> Result<TendermintValidatorPubKey, DistributionError> {
        if let Ok(key) = base64::decode(encoded) {
            let key_len = key.len();
            match (key_len, t) {
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

    fn is_rewards_pool_address(&self, address: &RedeemAddress) -> bool {
        *address == self.launch_incentive_from
            || *address == self.launch_incentive_to
            || *address == self.long_term_incentive
    }

    /// returns the initial accounts and rewards pool state
    /// assumes one called [validate_config_get_genesis], otherwise it may panic
    fn get_genesis_state(
        &self,
        genesis_time: Timespec,
        validator_addresses: HashSet<RedeemAddress>,
    ) -> (Vec<StakedState>, RewardsPoolState) {
        let mut rewards_pool_amount: u64 = 0;
        let mut accounts = Vec::with_capacity(self.distribution.len());
        for (address, (amount, address_type)) in self.distribution.iter() {
            if self.is_rewards_pool_address(address) || *address_type == AccountType::Contract {
                rewards_pool_amount += u64::from(*amount);
            } else {
                accounts.push(StakedState::new_init(
                    *amount,
                    genesis_time,
                    StakedStateAddress::BasicRedeem(*address),
                    validator_addresses.contains(address),
                ));
            }
        }
        (
            accounts,
            RewardsPoolState::new(
                Coin::new(rewards_pool_amount).expect("rewards pool amount"),
                0,
            ),
        )
    }

    /// checks if the config is valid:
    /// - required addresses are present in the distribution
    /// - initial validator configuration is correct
    /// - the total amount doesn't go over the maximum supply
    /// - ...
    /// if valid, it'll return the genesis "state"
    pub fn validate_config_get_genesis(
        &self,
        genesis_time: Timespec,
    ) -> Result<(Vec<StakedState>, RewardsPoolState, Vec<CouncilNode>), DistributionError> {
        self.check_address(&self.launch_incentive_from)?;
        self.check_address(&self.launch_incentive_to)?;
        self.check_address(&self.long_term_incentive)?;
        if self.council_nodes.is_empty() {
            return Err(DistributionError::NoValidators);
        }
        let mut validators = Vec::with_capacity(self.council_nodes.len());
        let mut validator_addresses = HashSet::new();
        let mut validator_pubkeys = HashSet::new();
        for node in self.council_nodes.iter() {
            if self.is_rewards_pool_address(&node.staking_account_address) {
                return Err(DistributionError::InvalidValidatorAccount);
            }
            if validator_addresses.contains(&node.staking_account_address) {
                return Err(DistributionError::DuplicateValidatorAccount);
            }

            self.check_address_expected_amount(
                &node.staking_account_address,
                self.network_params.required_council_node_stake,
            )?;
            let validator_key = InitConfig::check_validator_key(
                &node.consensus_pubkey_type,
                &node.consensus_pubkey_b64,
            )?;
            if validator_pubkeys.contains(&validator_key) {
                return Err(DistributionError::DuplicateValidatorKey);
            }
            validator_addresses.insert(node.staking_account_address);
            validator_pubkeys.insert(validator_key.clone());

            validator_addresses.insert(node.staking_account_address);
            validators.push(CouncilNode::new(
                StakedStateAddress::BasicRedeem(node.staking_account_address),
                validator_key,
            ));
        }
        let total_validator_stake = Coin::new(
            u64::from(self.network_params.required_council_node_stake)
                * self.council_nodes.len() as u64,
        );
        // sanity check
        match total_validator_stake {
            Ok(tvs) => TendermintVotePower::from(tvs),
            _ => {
                return Err(DistributionError::InvalidVotingPower);
            }
        };

        let sumr = sum_coins(self.distribution.iter().map(|(_, (amount, _))| *amount));
        match sumr {
            Ok(sum) => {
                if sum != Coin::max() {
                    Err(DistributionError::DoesNotMatchMaxSupply(sum))
                } else {
                    let (accounts, rewards_pool) =
                        self.get_genesis_state(genesis_time, validator_addresses);
                    Ok((accounts, rewards_pool, validators))
                }
            }
            Err(e) => Err(DistributionError::DistributionCoinError(e)),
        }
    }
}
