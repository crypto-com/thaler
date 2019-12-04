use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use hex::encode_upper;
use structopt::StructOpt;

use chain_abci::app::init_app_hash;
use chain_core::init::config::InitNetworkParameters;
use chain_core::init::{address::RedeemAddress, coin::Coin, config::InitConfig};
use chain_core::state::account::StakedStateDestination;
use chain_core::tx::fee::{LinearFee, Milli};
use client_common::tendermint::types::Time;
use client_common::{ErrorKind, Result, ResultExt};

use crate::commands::genesis_dev_config::GenesisDevConfig;

#[derive(Debug, StructOpt)]
pub enum GenesisCommand {
    #[structopt(
        name = "generate",
        about = "Generate new genesis.json parameters (app_hash + app_state)"
    )]
    Generate {
        #[structopt(
            name = "genesis_dev_config_path",
            short,
            long,
            help = "Path to a file containing the genesis-related configuration (e.g. ERC20 holdership) -- see example-dev-conf.json"
        )]
        genesis_dev_config_path: PathBuf,
    },
}

impl GenesisCommand {
    pub fn execute(&self) -> Result<()> {
        match self {
            GenesisCommand::Generate {
                genesis_dev_config_path,
            } => GenesisCommand::generate(&genesis_dev_config_path).map(|_| ()),
        }
    }

    pub fn do_generate(genesis_dev: &GenesisDevConfig) -> Result<(String, InitConfig)> {
        let mut dist: BTreeMap<RedeemAddress, (StakedStateDestination, Coin)> = BTreeMap::new();

        for (address, amount) in genesis_dev.distribution.iter() {
            let dest = if genesis_dev.council_nodes.contains_key(&address) {
                StakedStateDestination::Bonded
            } else {
                StakedStateDestination::UnbondedFromGenesis
            };
            dist.insert(*address, (dest, *amount));
        }
        let constant_fee = Milli::from_str(&genesis_dev.initial_fee_policy.base_fee)
            .chain(|| (ErrorKind::InvalidInput, "Invalid constant fee"))?;
        let coefficient_fee = Milli::from_str(&genesis_dev.initial_fee_policy.per_byte_fee)
            .chain(|| (ErrorKind::InvalidInput, "Invalid per byte fee"))?;
        let fee_policy = LinearFee::new(constant_fee, coefficient_fee);
        let network_params = InitNetworkParameters {
            initial_fee_policy: fee_policy,
            required_council_node_stake: genesis_dev.required_council_node_stake,
            unbonding_period: genesis_dev.unbonding_period,
            jailing_config: genesis_dev.jailing_config,
            slashing_config: genesis_dev.slashing_config,
            rewards_config: genesis_dev.rewards_config,
            max_validators: 50,
        };
        let config = InitConfig::new(dist, network_params, genesis_dev.council_nodes.clone());
        let genesis_app_hash = init_app_hash(
            &config,
            genesis_dev
                .genesis_time
                .duration_since(Time::unix_epoch())
                .expect("invalid genesis time")
                .as_secs(),
        );

        println!("\"app_hash\": \"{}\",", encode_upper(genesis_app_hash));
        let config_str = serde_json::to_string_pretty(&config)
            .chain(|| (ErrorKind::InvalidInput, "Invalid config"))?;
        println!("\"app_state\": {}", config_str);
        println!();

        // app_hash, app_state
        Ok((encode_upper(genesis_app_hash), config))
    }
    pub fn generate(genesis_dev_config_path: &PathBuf) -> Result<(String, InitConfig)> {
        let genesis_dev_config = fs::read_to_string(genesis_dev_config_path).chain(|| {
            (
                ErrorKind::InvalidInput,
                "Something went wrong reading the file",
            )
        })?;
        let genesis_dev: GenesisDevConfig =
            serde_json::from_str(&genesis_dev_config).expect("failed to parse genesis dev config");

        GenesisCommand::do_generate(&genesis_dev)
    }
}
