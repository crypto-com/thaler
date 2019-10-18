use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::init::config::{
    AccountType, InitConfig, InitNetworkParameters, InitialValidator, JailingParameters,
    SlashRatio, SlashingParameters, ValidatorKeyType,
};
use chain_core::tx::fee::{LinearFee, Milli};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::str::FromStr;

#[derive(Deserialize)]
pub struct Distribution {
    contract: Vec<ERC20Holder>,
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
    let mut dist: BTreeMap<RedeemAddress, (Coin, AccountType)> = BTreeMap::new();
    for contract_account in distribution.contract.iter() {
        let amount = Coin::new(contract_account.balance.parse::<u64>().expect("amount")).unwrap();
        dist.insert(contract_account.address, (amount, AccountType::Contract));
    }
    for account in distribution.eoa.iter() {
        let amount = Coin::new(account.balance.parse::<u64>().expect("amount")).unwrap();
        dist.insert(
            account.address,
            (amount, AccountType::ExternallyOwnedAccount),
        );
    }
    let constant_fee = Milli::new(1, 25);
    let coefficient_fee = Milli::new(1, 1);
    let fee_policy = LinearFee::new(constant_fee, coefficient_fee);
    let params = InitNetworkParameters {
        initial_fee_policy: fee_policy,
        required_council_node_stake: Coin::new(50_000_000_0000_0000).unwrap(),
        unbonding_period: 86400,
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
    };
    let launch_incentive_from = "0x35f517cab9a37bc31091c2f155d965af84e0bc85"
        .parse::<RedeemAddress>()
        .unwrap();
    let launch_incentive_to = "0x20a0bee429d6907e556205ef9d48ab6fe6a55531"
        .parse::<RedeemAddress>()
        .unwrap();
    let long_term_incentive = "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07"
        .parse::<RedeemAddress>()
        .unwrap();
    let example_validator = InitialValidator {
        staking_account_address: "0x2440ad2533c66d91eb97807a339be13556d04990"
            .parse::<RedeemAddress>()
            .unwrap(),
        consensus_pubkey_type: ValidatorKeyType::Ed25519,
        consensus_pubkey_b64: "EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=".to_string(),
    };
    let config = InitConfig::new(
        dist,
        launch_incentive_from,
        launch_incentive_to,
        long_term_incentive,
        params,
        vec![example_validator],
    );
    let result = config.validate_config_get_genesis(0);
    assert!(result.is_ok());
}
