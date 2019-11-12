use std::{collections::BTreeMap, str::FromStr};

use chrono::{offset::Utc, DateTime};
use serde::{Deserialize, Serialize};

use chain_core::init::{
    address::RedeemAddress,
    coin::Coin,
    config::{JailingParameters, SlashRatio, SlashingParameters, ValidatorPubkey},
};
use chain_core::state::account::{ValidatorName, ValidatorSecurityContact};

#[derive(Deserialize, Debug)]
pub struct GenesisDevConfig {
    pub rewards_pool: Coin,
    pub distribution: BTreeMap<RedeemAddress, Coin>,
    pub unbonding_period: u32,
    pub required_council_node_stake: Coin,
    pub jailing_config: JailingParameters,
    pub slashing_config: SlashingParameters,
    pub initial_fee_policy: InitialFeePolicy,
    pub council_nodes:
        BTreeMap<RedeemAddress, (ValidatorName, ValidatorSecurityContact, ValidatorPubkey)>,
    pub genesis_time: DateTime<Utc>,
}

impl GenesisDevConfig {
    pub fn new(rewards_pool: Coin) -> Self {
        let gt = DateTime::parse_from_rfc3339("2019-03-21T02:26:51.366017Z").unwrap();
        GenesisDevConfig {
            rewards_pool,
            distribution: BTreeMap::new(),
            unbonding_period: 60,
            required_council_node_stake: Coin::new(1_250_000_000_000_000_000).unwrap(),
            jailing_config: JailingParameters {
                jail_duration: 86400,
                block_signing_window: 100,
                missed_block_threshold: 50,
            },
            slashing_config: SlashingParameters {
                liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
                byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
                slash_wait_period: 10800,
            },
            initial_fee_policy: InitialFeePolicy {
                base_fee: "1.1".to_string(),
                per_byte_fee: "1.25".to_string(),
            },
            council_nodes: BTreeMap::new(),
            genesis_time: DateTime::from(gt),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InitialFeePolicy {
    pub base_fee: String,
    pub per_byte_fee: String,
}
