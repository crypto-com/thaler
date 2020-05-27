use crate::common::Timespec;
use crate::init::address::RedeemAddress;
use crate::init::coin::{sum_coins, Coin, CoinError};
pub use crate::init::params::*;
use crate::state::account::{
    ConfidentialInit, CouncilNode, StakedState, StakedStateAddress, StakedStateDestination,
    ValidatorName, ValidatorSecurityContact,
};
use crate::state::tendermint::TendermintValidatorPubKey;
use crate::state::RewardsPoolState;
use mls::{keypackage, Codec, KeyPackage};
use ra_client::ENCLAVE_CERT_VERIFIER;
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// problems with initial config
#[derive(thiserror::Error, Debug)]
pub enum DistributionError {
    /// coin arithmetic problems
    #[error("coin error: {0}")]
    DistributionCoinError(#[from] CoinError),
    /// lower than the expected supply
    #[error("The total sum of allocated amounts ({0}) does not match the expected total supply")]
    DoesNotMatchMaxSupply(Coin),
    /// council node uses non-specified address
    #[error("Address not found in the distribution ({0})")]
    AddressNotInDistribution(RedeemAddress),
    /// address should have that amount assigned
    #[error("Address ({0}) does not have the expected amount ({1}) or is not an externally owned account")]
    DoesNotMatchRequiredAmount(RedeemAddress, Coin),
    /// problems with encoded consensus pubkeys
    #[error("Invalid validator key")]
    InvalidValidatorKey,
    /// duplicate consensus pubkeys
    #[error("Duplicate validator key")]
    DuplicateValidatorKey,
    /// associated state not in distribution
    #[error("Invalid validator account")]
    InvalidValidatorAccount,
    /// at least one validator needs to be specified
    #[error("No validators / council nodes specified")]
    NoValidators,
    /// voting power too large or otherwise invalid
    #[error("Invalid minimal required staking: {0}")]
    InvalidMinimalStake(CoinError),
    /// problems with reward configuration
    /// TODO: embed the error type?
    #[error("Invalid rewards parameters: {0}")]
    InvalidRewardsParamter(&'static str),
    /// Invalid punishment configuration parameter
    #[error("Invalid punishment parameters")]
    InvalidPunishmentParamter,
    /// keypackage decode error
    #[error("key package decode failed")]
    KeyPackageDecodeError,
    /// keypackage verify error
    #[error("invalid key package: {0}")]
    KeyPackageVerifyError(#[from] keypackage::Error),
}

/// Initial configuration ("app_state" in genesis.json of Tendermint config)
/// TODO: reward/treasury config, extra validator config...
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct InitConfig {
    /// Redeem mapping of ERC20 snapshot: Eth address => (StakedStateDestination,CRO tokens)
    /// (doesn't include the rewards pool amount)
    pub distribution: BTreeMap<RedeemAddress, (StakedStateDestination, Coin)>,
    /// initial network parameters
    pub network_params: InitNetworkParameters,
    /// initial validators
    pub council_nodes: BTreeMap<
        RedeemAddress,
        (
            ValidatorName,
            ValidatorSecurityContact,
            TendermintValidatorPubKey,
            ConfidentialInit,
        ),
    >,
}

/// the initial state at genesis
pub struct GenesisState {
    /// initial states
    pub accounts: Vec<StakedState>,
    /// initial rewards pool
    pub rewards_pool: RewardsPoolState,
    /// initial tendermint validators
    pub validators: Vec<(StakedStateAddress, CouncilNode)>,
    /// enclave ISVSVN in genesis keypackage
    pub isv_svn: u16,
}

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
                ConfidentialInit,
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
    pub fn get_account(&self, genesis_time: Timespec) -> Vec<StakedState> {
        self.distribution
            .iter()
            .map(|(address, (destination, amount))| {
                StakedState::from_genesis(
                    StakedStateAddress::BasicRedeem(*address),
                    genesis_time,
                    destination,
                    *amount,
                    // assume address already validated, so we just ignore any error here.
                    self.get_council_node(address).ok(),
                )
            })
            .collect()
    }

    fn get_council_node(&self, address: &RedeemAddress) -> Result<CouncilNode, DistributionError> {
        self.check_validator_address(address)?;
        let (name, security_contact, pubkey, confidential_init) =
            self.council_nodes
                .get(address)
                .ok_or(DistributionError::InvalidValidatorAccount)?;
        Ok(CouncilNode::new_with_details(
            name.clone(),
            security_contact.clone(),
            pubkey.clone(),
            confidential_init.clone(),
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
        let jailing_config = &self.network_params.jailing_config;
        if jailing_config.missed_block_threshold > jailing_config.block_signing_window {
            return Err(DistributionError::InvalidPunishmentParamter);
        }
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

        let validators = self
            .council_nodes
            .keys()
            .map(|address| {
                let council_node = self.get_council_node(address)?;
                Ok((StakedStateAddress::BasicRedeem(*address), council_node))
            })
            .collect::<Result<Vec<_>, DistributionError>>()?;

        let isv_svn = validators
            .iter()
            .map(|v| verify_keypackage(genesis_time, &v.1.confidential_init.keypackage))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .unwrap_or(0);

        Coin::new(
            u64::from(self.network_params.required_council_node_stake)
                * self.council_nodes.len() as u64,
        )
        .map_err(DistributionError::InvalidMinimalStake)?;

        // check the total amount
        let sum = sum_coins(self.distribution.iter().map(|(_, (_, amount))| *amount))?;
        let sum = (sum + self.network_params.rewards_config.monetary_expansion_cap)?;
        if sum != Coin::max() {
            return Err(DistributionError::DoesNotMatchMaxSupply(sum));
        }

        let accounts = self.get_account(genesis_time);
        #[cfg(debug_assertions)]
        for staking in accounts.iter() {
            staking.check_invariants(self.network_params.required_council_node_stake);
        }
        let rewards_pool = RewardsPoolState::new(
            genesis_time,
            self.network_params.rewards_config.monetary_expansion_tau,
        );
        Ok(GenesisState {
            accounts,
            rewards_pool,
            validators,
            isv_svn,
        })
    }
}

fn verify_keypackage(genesis_time: Timespec, keypackage: &[u8]) -> Result<u16, DistributionError> {
    let keypackage =
        KeyPackage::read_bytes(keypackage).ok_or(DistributionError::KeyPackageDecodeError)?;
    let info = keypackage
        .verify(&ENCLAVE_CERT_VERIFIER, genesis_time)
        .map_err(DistributionError::KeyPackageVerifyError)?;
    Ok(info.quote.report_body.isv_svn)
}
