use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::init::config::{
    InitConfig, InitNetworkParameters, JailingParameters, RewardsParameters, SlashRatio,
    SlashingParameters,
};
use chain_core::state::account::{ConfidentialInit, StakedStateDestination};
use chain_core::state::tendermint::TendermintValidatorPubKey;
use chain_core::tx::fee::{LinearFee, Milli};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::str::FromStr;

#[derive(Deserialize)]
pub struct Distribution {
    #[serde(rename = "EOA")]
    eoa: Vec<ERC20Holder>,
}

#[derive(Deserialize)]
pub struct ERC20Holder {
    address: RedeemAddress,
    balance: String,
}

#[test]
fn test_verify_test_example_snapshot() {
    let distribution_txt = include_str!("distribution.json");
    let distribution: Distribution = serde_json::from_str(&distribution_txt).unwrap();
    let node_address = "0x2440ad2533c66d91eb97807a339be13556d04990"
        .parse::<RedeemAddress>()
        .unwrap();
    let node_pubkey =
        TendermintValidatorPubKey::from_base64(b"EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=")
            .unwrap();
    let mut nodes = BTreeMap::new();
    nodes.insert(
        node_address,
        (
            "no-name".to_owned(),
            None,
            node_pubkey,
            ConfidentialInit { cert: vec![] },
        ),
    );

    let mut dist: BTreeMap<RedeemAddress, (StakedStateDestination, Coin)> = BTreeMap::new();

    for account in distribution.eoa.iter() {
        let amount = Coin::new(account.balance.parse::<u64>().expect("amount")).unwrap();
        let dest = if nodes.contains_key(&account.address) {
            StakedStateDestination::Bonded
        } else {
            StakedStateDestination::UnbondedFromGenesis
        };
        dist.insert(account.address, (dest, amount));
    }
    let constant_fee = Milli::try_new(1, 25).unwrap();
    let coefficient_fee = Milli::try_new(1, 1).unwrap();
    let fee_policy = LinearFee::new(constant_fee, coefficient_fee);
    let expansion_cap = Coin::new(951_6484_5705_9733_7034).unwrap();
    let mut params = InitNetworkParameters {
        initial_fee_policy: fee_policy,
        required_council_node_stake: Coin::new(5000_0000_0000_0000).unwrap(),
        unbonding_period: 86400,
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
            monetary_expansion_r0: "0.5".parse().unwrap(),
            monetary_expansion_tau: 166666600,
            monetary_expansion_decay: 999860,
        },
        max_validators: 1,
    };

    let config = InitConfig::new(dist.clone(), params.clone(), nodes.clone());
    let result = config.validate_config_get_genesis(0);
    assert!(result.is_ok());

    // add 1 into rewards_pool
    params.rewards_config.monetary_expansion_cap = Coin::new(951_6484_5705_9733_7035).unwrap();
    let config = InitConfig::new(dist, params, nodes);
    let result = config.validate_config_get_genesis(0);
    assert!(result.is_err());
}
