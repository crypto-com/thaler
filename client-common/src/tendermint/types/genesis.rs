#![allow(missing_docs)]

use chrono::offset::Utc;
use chrono::DateTime;
use serde::Deserialize;

use chain_core::init::config::InitConfig;
use chain_core::tx::fee::LinearFee;

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
    /// Returns time of genesis
    pub fn time(&self) -> DateTime<Utc> {
        self.genesis.genesis_time
    }

    /// Returns initial_fee_policy
    pub fn fee_policy(&self) -> LinearFee {
        self.genesis.app_state.network_params.initial_fee_policy
    }
}
