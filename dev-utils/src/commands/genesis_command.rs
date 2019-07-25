use std::str::FromStr;

use failure::{format_err, Error, ResultExt};
use hex::encode_upper;
use structopt::StructOpt;

use chain_abci::storage::account::{AccountStorage, AccountWrapper};
use chain_abci::storage::tx::StarlingFixedKey;
use chain_abci::storage::Storage;
use chain_core::common::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::init::config::{AccountType, InitNetworkParameters, InitialValidator};
use chain_core::init::{address::RedeemAddress, coin::Coin, config::InitConfig};
use chain_core::state::account::StakedState;
use chain_core::tx::fee::{LinearFee, Milli};
use chrono::offset::Utc;
use chrono::DateTime;
use kvdb_memorydb::create;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
pub struct GenesisDevConfig {
    distribution: BTreeMap<RedeemAddress, Coin>,
    unbonding_period: u32,
    required_council_node_stake: Coin,
    initial_fee_policy: InitialFeePolicy,
    council_nodes: Vec<InitialValidator>,
    launch_incentive_from: RedeemAddress,
    launch_incentive_to: RedeemAddress,
    long_term_incentive: RedeemAddress,
    pub genesis_time: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InitialFeePolicy {
    base_fee: String,
    per_byte_fee: String,
}

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
    pub fn execute(&self) -> Result<(), Error> {
        match self {
            GenesisCommand::Generate {
                genesis_dev_config_path,
            } => GenesisCommand::generate(&genesis_dev_config_path).map(|_e| ()),
        }
    }

    pub fn generate(genesis_dev_config_path: &PathBuf) -> Result<(String, String), Error> {
        let genesis_dev_config = fs::read_to_string(genesis_dev_config_path)
            .context(format_err!("Something went wrong reading the file"))?;
        let genesis_dev: GenesisDevConfig =
            serde_json::from_str(&genesis_dev_config).expect("failed to parse genesis dev config");
        let mut dist: BTreeMap<RedeemAddress, (Coin, AccountType)> = BTreeMap::new();

        for (address, amount) in genesis_dev.distribution.iter() {
            dist.insert(*address, (*amount, AccountType::ExternallyOwnedAccount));
        }
        let constant_fee = Milli::from_str(&genesis_dev.initial_fee_policy.base_fee)
            .context(format_err!("Invalid constant fee"))?;
        let coefficient_fee = Milli::from_str(&genesis_dev.initial_fee_policy.per_byte_fee)
            .context(format_err!("Invalid per byte fee"))?;
        let fee_policy = LinearFee::new(constant_fee, coefficient_fee);
        let params = InitNetworkParameters {
            initial_fee_policy: fee_policy,
            required_council_node_stake: genesis_dev.required_council_node_stake,
            unbonding_period: genesis_dev.unbonding_period,
        };
        let config = InitConfig::new(
            dist,
            genesis_dev.launch_incentive_from,
            genesis_dev.launch_incentive_to,
            genesis_dev.long_term_incentive,
            params,
            genesis_dev.council_nodes,
        );
        let result = config.validate_config_get_genesis(genesis_dev.genesis_time.timestamp());
        if let Ok((accounts, rp, _nodes)) = result {
            let tx_tree = MerkleTree::empty();
            let mut account_tree =
                AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db");

            let keys: Vec<StarlingFixedKey> = accounts.iter().map(StakedState::key).collect();
            // TODO: get rid of the extra allocations
            let wrapped: Vec<AccountWrapper> =
                accounts.iter().map(|x| AccountWrapper(x.clone())).collect();
            let new_account_root = account_tree
                .insert(
                    None,
                    &mut keys.iter().collect::<Vec<_>>(),
                    &mut wrapped.iter().collect::<Vec<_>>(),
                )
                .expect("initial insert");

            let genesis_app_hash = compute_app_hash(&tx_tree, &new_account_root, &rp);
            println!("\"app_hash\": \"{}\",", encode_upper(genesis_app_hash));
            let config_str =
                serde_json::to_string(&config).context(format_err!("Invalid config"))?;
            println!("\"app_state\": {}", config_str);
            println!();

            // app_hash, app_state
            Ok((encode_upper(genesis_app_hash), config_str))
        } else {
            Err(format_err!(
                "distribution validation error: {} ",
                result.unwrap_err()
            ))
        }
    }
}
