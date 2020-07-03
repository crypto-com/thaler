use std::{collections::BTreeMap, str::FromStr};

use serde::{Deserialize, Serialize};

use chain_core::init::{
    address::RedeemAddress,
    coin::Coin,
    config::{JailingParameters, RewardsParameters, SlashRatio, SlashingParameters},
};
use chain_core::state::account::{ConfidentialInit, NodeName, NodeSecurityContact};
use chain_core::state::tendermint::TendermintValidatorPubKey;

#[derive(Deserialize, Debug)]
pub struct GenesisDevConfig {
    pub distribution: BTreeMap<RedeemAddress, Coin>,
    pub required_council_node_stake: Coin,
    pub jailing_config: JailingParameters,
    pub slashing_config: SlashingParameters,
    pub rewards_config: RewardsParameters,
    pub initial_fee_policy: InitialFeePolicy,
    pub evidence: Evidence,
    pub council_nodes: BTreeMap<
        RedeemAddress,
        (
            NodeName,
            NodeSecurityContact,
            TendermintValidatorPubKey,
            ConfidentialInit,
        ),
    >,
}

impl GenesisDevConfig {
    pub fn new(expansion_cap: Coin) -> Self {
        GenesisDevConfig {
            distribution: BTreeMap::new(),
            required_council_node_stake: Coin::new(1_250_000_000_000_000_000).unwrap(),
            jailing_config: JailingParameters {
                block_signing_window: 100,
                missed_block_threshold: 50,
            },
            slashing_config: SlashingParameters {
                liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
                byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            },
            rewards_config: RewardsParameters {
                monetary_expansion_cap: expansion_cap,
                reward_period_seconds: 24 * 60 * 60,
                monetary_expansion_r0: "0.45".parse().unwrap(),
                monetary_expansion_tau: 1_4500_0000_0000_0000,
                monetary_expansion_decay: 999_860,
            },
            initial_fee_policy: InitialFeePolicy {
                base_fee: "1.1".to_string(),
                per_byte_fee: "1.25".to_string(),
            },
            evidence: Evidence {
                max_age_duration: "5400000000000".into(),
                max_age_num_blocks: "200".into(),
            },
            council_nodes: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InitialFeePolicy {
    pub base_fee: String,
    pub per_byte_fee: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    pub max_age_duration: String,
    pub max_age_num_blocks: String,
}
