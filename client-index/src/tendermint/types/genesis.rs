#![allow(missing_docs)]

use failure::ResultExt;
use hex::decode;
use serde::{Deserialize, Serialize};

use chain_core::init::config::InitConfig;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::Tx;
use client_common::{ErrorKind, Result};

#[cfg(test)]
use chain_core::init::address::RedeemAddress;
#[cfg(test)]
use chain_core::init::coin::Coin;
#[cfg(test)]
use chain_core::init::config::ERC20Owner;
#[cfg(test)]
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub struct Genesis {
    genesis: GenesisInner,
}

#[derive(Debug, Serialize, Deserialize)]
struct GenesisInner {
    chain_id: String,
    app_state: InitConfig,
}

impl Genesis {
    /// Returns genesis transactions
    pub fn transactions(&self) -> Result<Vec<Tx>> {
        let (_, chain_id) = self
            .genesis
            .chain_id
            .split_at(self.genesis.chain_id.len() - 2);
        let chain_id = decode(chain_id).context(ErrorKind::DeserializationError)?[0];

        let app_state = &self.genesis.app_state;

        let transactions = app_state.generate_utxos(&TxAttributes::new(chain_id));

        Ok(transactions)
    }
}

// Note: Do not change these values. These are tied with tests for `RpcSledIndex`
#[cfg(test)]
impl Default for Genesis {
    fn default() -> Self {
        Genesis {
            genesis: GenesisInner {
                chain_id: "test-chain-4UIy1Wab".to_owned(),
                app_state: InitConfig::new(vec![ERC20Owner::new(
                    RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
                    Coin::new(10000000000000000000).unwrap(),
                )]),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_transactions() {
        let genesis = Genesis::default();
        assert_eq!(1, genesis.transactions().unwrap().len());
    }

    #[test]
    fn check_wrong_transaction() {
        let genesis = Genesis {
            genesis: GenesisInner {
                chain_id: "test-chain-4UIy1Wb".to_owned(),
                app_state: InitConfig::new(vec![ERC20Owner::new(
                    RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
                    Coin::new(10000000000000000000).unwrap(),
                )]),
            },
        };

        assert!(genesis.transactions().is_err());
    }
}
