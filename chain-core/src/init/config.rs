use std::fmt;

use serde::{Deserialize, Serialize};

use crate::init::address::RedeemAddress;
use crate::init::coin::{sum_coins, Coin, CoinError};
use crate::init::MAX_COIN;
use crate::state::RewardsPoolState;
use crate::tx::data::{address::ExtendedAddr, attribute::TxAttributes, output::TxOut, Tx};
use crate::tx::fee::LinearFee;
use std::collections::BTreeMap;

/// Initial configuration ("app_state" in genesis.json of Tendermint config)
/// TODO: reward/treasury config, extra validator config...
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct InitConfig {
    // Redeem mapping of ERC20 snapshot: Eth address => CRO tokens
    pub distribution: BTreeMap<RedeemAddress, Coin>,
    // 0x35f517cab9a37bc31091c2f155d965af84e0bc85 on Eth mainnet ERC20
    pub launch_incentive_from: RedeemAddress,
    // 0x20a0bee429d6907e556205ef9d48ab6fe6a55531 on Eth mainnet ERC20
    pub launch_incentive_to: RedeemAddress,
    // 0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07 on Eth mainnet ERC20
    pub long_term_incentive: RedeemAddress,
    // Initial fee setting
    // -- TODO: perhaps change to be against T: FeeAlgorithm
    // TBD here, the intention would be to "freeze" the genesis config, so not sure generic field is worth it
    pub initial_fee_policy: LinearFee,
}

pub enum DistributionError {
    DistributionCoinError(CoinError),
    DoesNotMatchMaxSupply,
    AddressNotInDistribution(RedeemAddress),
}

impl fmt::Display for DistributionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DistributionError::DistributionCoinError(c) => c.fmt(f),
            DistributionError::DoesNotMatchMaxSupply => write!(
                f,
                "The total sum of allocated amounts does not match the expected total supply ({})",
                MAX_COIN
            ),
            DistributionError::AddressNotInDistribution(a) => {
                write!(f, "Address not found in the distribution ({})", a)
            }
        }
    }
}

impl InitConfig {
    /// creates a new config (mainly for testing / tools)
    pub fn new(
        owners: BTreeMap<RedeemAddress, Coin>,
        launch_incentive_from: RedeemAddress,
        launch_incentive_to: RedeemAddress,
        long_term_incentive: RedeemAddress,
        initial_fee_policy: LinearFee,
    ) -> Self {
        InitConfig {
            distribution: owners,
            launch_incentive_from,
            launch_incentive_to,
            long_term_incentive,
            initial_fee_policy,
        }
    }

    /// generates "genesis transactions" (no inputs, only outputs)
    pub fn generate_utxos(&self, attributes: &TxAttributes) -> Vec<Tx> {
        self.distribution
            .iter()
            .filter(|(aref, _)| {
                let address = **aref;
                address != self.launch_incentive_from
                    && address != self.launch_incentive_to
                    && address != self.long_term_incentive
            })
            .map(|(address, amount)| {
                Tx::new_with(
                    Vec::new(),
                    vec![TxOut::new(ExtendedAddr::BasicRedeem(*address), *amount)],
                    attributes.clone(),
                )
            })
            .collect()
    }

    fn check_address(&self, address: &RedeemAddress) -> Result<(), DistributionError> {
        if self.distribution.contains_key(address) {
            Ok(())
        } else {
            Err(DistributionError::AddressNotInDistribution(*address))
        }
    }

    /// returns the initial rewards pool state
    /// assumes one called [validate_distribution], otherwise it may panic
    pub fn get_genesis_rewards_pool(&self) -> RewardsPoolState {
        // for some reason, type inference goes bonkers when one calls [sum_coins] in rustc 1.34.1 (fc50f328b 2019-04-24)
        // hence inlined the fold
        // TODO: replace with sum_coins if possible, or file a bug in rustc
        let amount = [
            *self
                .distribution
                .get(&self.launch_incentive_from)
                .expect("launch incentives from address"),
            *self
                .distribution
                .get(&self.launch_incentive_to)
                .expect("launch incentives to address"),
            *self
                .distribution
                .get(&self.long_term_incentive)
                .expect("long term incentives address"),
        ]
        .iter()
        .fold(Coin::new(0), |acc, c| acc.and_then(|v| v + c));
        RewardsPoolState::new(amount.expect("rewards pool amount"), 0)
    }

    /// checks if distribution is valid -- i.e. contains correct amounts and matches the expected total supply
    /// and all rewards pool addresses are present
    pub fn validate_distribution(&self) -> Result<(), DistributionError> {
        self.check_address(&self.launch_incentive_from)?;
        self.check_address(&self.launch_incentive_to)?;
        self.check_address(&self.long_term_incentive)?;
        let sumr = sum_coins(self.distribution.iter().map(|(_, amount)| *amount));
        match sumr {
            Ok(sum) => {
                if sum != Coin::max() {
                    Err(DistributionError::DoesNotMatchMaxSupply)
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(DistributionError::DistributionCoinError(e)),
        }
    }
}
