use std::fmt;

use serde::{Deserialize, Serialize};

use crate::init::address::RedeemAddress;
use crate::init::coin::{sum_coins, Coin, CoinError};
use crate::init::MAX_COIN;
use crate::tx::data::{address::ExtendedAddr, attribute::TxAttributes, output::TxOut, Tx};

/// Redeem mapping Eth address => CRO tokens
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ERC20Owner {
    pub address: RedeemAddress,
    pub amount: Coin,
}

impl ERC20Owner {
    /// creates a new mapping (mainly for testing / tools)
    pub fn new(address: RedeemAddress, amount: Coin) -> Self {
        ERC20Owner { address, amount }
    }
}

/// Initial configuration ("app_state" in genesis.json of Tendermint config)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct InitConfig {
    // TODO: reward/treasury config, extra validator config, fee...
    pub distribution: Vec<ERC20Owner>,
}

pub enum DistributionError {
    DistributionCoinError(CoinError),
    DoesNotMatchMaxSupply,
}

impl fmt::Display for DistributionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DistributionError::DistributionCoinError(c) => c.fmt(f),
            DistributionError::DoesNotMatchMaxSupply => write!(
                f,
                "The total sum of allocated amounts does not match the expected total supply ({})",
                MAX_COIN
            ),
        }
    }
}

impl InitConfig {
    /// creates a new config (mainly for testing / tools)
    pub fn new(owners: Vec<ERC20Owner>) -> Self {
        InitConfig {
            distribution: owners,
        }
    }

    /// generates "genesis transactions" (no inputs, only outputs)
    pub fn generate_utxos(&self, attributes: &TxAttributes) -> Vec<Tx> {
        self.distribution
            .iter()
            .map(|x| {
                Tx::new_with(
                    Vec::new(),
                    vec![TxOut::new(ExtendedAddr::BasicRedeem(x.address.0), x.amount)],
                    attributes.clone(),
                )
            })
            .collect()
    }

    /// checks if distribution is valid -- i.e. contains correct amounts and matches the expected total supply
    pub fn validate_distribution(&self) -> Result<(), DistributionError> {
        let sumr = sum_coins(self.distribution.iter().map(|x| x.amount));
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
