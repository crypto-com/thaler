use std::{collections::BTreeMap, str::FromStr};

use chrono::{offset::Utc, DateTime};
use serde::{Deserialize, Serialize};

use chain_core::init::{address::RedeemAddress, coin::Coin, config::InitialValidator};

#[derive(Deserialize, Debug)]
pub struct GenesisDevConfig {
    pub distribution: BTreeMap<RedeemAddress, Coin>,
    pub unbonding_period: u32,
    pub required_council_node_stake: Coin,
    pub jail_duration: u32,
    pub max_allowed_faulty_blocks: u16,
    pub initial_fee_policy: InitialFeePolicy,
    pub council_nodes: Vec<InitialValidator>,
    pub launch_incentive_from: RedeemAddress,
    pub launch_incentive_to: RedeemAddress,
    pub long_term_incentive: RedeemAddress,
    pub genesis_time: DateTime<Utc>,
}

impl GenesisDevConfig {
    pub fn new() -> Self {
        let gt = DateTime::parse_from_rfc3339("2019-03-21T02:26:51.366017Z").unwrap();
        GenesisDevConfig {
            distribution: BTreeMap::new(),
            unbonding_period: 60,
            required_council_node_stake: Coin::new(1_250_000_000_000_000_000).unwrap(),
            jail_duration: 86400,
            max_allowed_faulty_blocks: 50,
            initial_fee_policy: InitialFeePolicy {
                base_fee: "1.1".to_string(),
                per_byte_fee: "1.25".to_string(),
            },
            council_nodes: vec![],
            launch_incentive_from: RedeemAddress::from_str(
                "0x35f517cab9a37bc31091c2f155d965af84e0bc85",
            )
            .unwrap(),
            launch_incentive_to: RedeemAddress::from_str(
                "0x20a0bee429d6907e556205ef9d48ab6fe6a55531",
            )
            .unwrap(),
            long_term_incentive: RedeemAddress::from_str(
                "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07",
            )
            .unwrap(),
            genesis_time: DateTime::from(gt),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InitialFeePolicy {
    pub base_fee: String,
    pub per_byte_fee: String,
}
