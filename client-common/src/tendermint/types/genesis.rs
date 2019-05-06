#![allow(missing_docs)]

use chrono::offset::Utc;
use chrono::DateTime;
use failure::ResultExt;
use hex::decode;
use serde::Deserialize;

use chain_core::init::config::InitConfig;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::Tx;

use crate::{ErrorKind, Result};

#[derive(Debug, Deserialize)]
pub struct Genesis {
    pub genesis: GenesisInner,
}

#[derive(Debug, Deserialize)]
pub struct GenesisInner {
    pub genesis_time: DateTime<Utc>,
    pub chain_id: String,
    pub app_state: InitConfig,
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

    /// Returns time of genesis
    pub fn time(&self) -> DateTime<Utc> {
        self.genesis.genesis_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;
    use std::time::SystemTime;

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use std::collections::BTreeMap;

    #[test]
    fn check_transactions() {
        let time = DateTime::from(SystemTime::now());
        let distribution: BTreeMap<RedeemAddress, Coin> = [(
            RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
            Coin::max(),
        )]
        .iter()
        .cloned()
        .collect();
        let genesis = Genesis {
            genesis: GenesisInner {
                genesis_time: time,
                chain_id: "test-chain-4UIy1Wab".to_owned(),
                app_state: InitConfig::new(
                    distribution,
                    RedeemAddress::default(),
                    RedeemAddress::default(),
                    RedeemAddress::default(),
                ),
            },
        };
        assert_eq!(1, genesis.transactions().unwrap().len());
        assert_eq!(time, genesis.time());
    }

    #[test]
    fn check_wrong_transaction() {
        let distribution: BTreeMap<RedeemAddress, Coin> = [(
            RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
            Coin::max(),
        )]
        .iter()
        .cloned()
        .collect();

        // wrong chain_id (not ending with hexadecimal)
        let genesis = Genesis {
            genesis: GenesisInner {
                genesis_time: DateTime::from(SystemTime::now()),
                chain_id: "test-chain-4UIy1Wb".to_owned(),
                app_state: InitConfig::new(
                    distribution,
                    RedeemAddress::default(),
                    RedeemAddress::default(),
                    RedeemAddress::default(),
                ),
            },
        };

        assert!(genesis.transactions().is_err());
    }
}
