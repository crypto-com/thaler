use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use hex::encode_upper;
use structopt::StructOpt;

use chain_abci::app::init_app_hash;
use chain_core::common::Timespec;
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::init::config::{InitConfig, InitNetworkParameters};
use chain_core::state::account::StakedStateDestination;
use chain_core::state::tendermint::{
    TendermintValidator, TendermintValidatorAddress, TendermintVotePower,
};
use chain_core::tx::fee::{LinearFee, Milli};
use client_common::tendermint::types::Time;
use client_common::{ErrorKind, Result, ResultExt};

use crate::commands::genesis_dev_config::GenesisDevConfig;

#[derive(Debug, StructOpt)]
pub enum GenesisCommand {
    #[structopt(name = "generate", about = "Generate new genesis.json")]
    Generate {
        #[structopt(
            name = "tendermint_genesis_path",
            short,
            long,
            help = "Path to the Tendermint genesis.json file (e.g. ~/.tendermint/config/genesis.json)"
        )]
        tendermint_genesis_path: Option<PathBuf>,

        #[structopt(
            name = "genesis_dev_config_path",
            short,
            long,
            help = "Path to a file containing the genesis-related configuration (e.g. ERC20 holdership) -- see example-dev-conf.json"
        )]
        genesis_dev_config_path: PathBuf,

        #[structopt(
            name = "in_place",
            short,
            long,
            help = "Replace Tendermint genesis.json file in place"
        )]
        in_place: bool,

        #[structopt(
            name = "no_backup",
            short,
            long,
            help = "Don't create backup file when modify in place, default is creating backup file genesis.bak.json in the same directory"
        )]
        no_backup: bool,

        #[structopt(
            name = "unbonded_address",
            short,
            long,
            help = "If unbonded address is provided, all other staking addresses will be `Bonded` from genesis except from `unbonded_address`"
        )]
        unbonded_address: Option<String>,
    },
}

impl GenesisCommand {
    pub fn execute(&self) -> Result<()> {
        match self {
            GenesisCommand::Generate {
                tendermint_genesis_path,
                genesis_dev_config_path,
                in_place,
                no_backup,
                unbonded_address,
            } => generate_genesis_command(
                tendermint_genesis_path,
                genesis_dev_config_path,
                *in_place,
                *no_backup,
                unbonded_address,
            )
            .map(|_| ()),
        }
    }
}

fn generate_genesis_command(
    tendermint_genesis_path: &Option<PathBuf>,
    genesis_dev_config_path: &PathBuf,
    in_place: bool,
    no_backup: bool,
    unbonded_address: &Option<String>,
) -> Result<()> {
    let tendermint_genesis_path = match tendermint_genesis_path {
        Some(path) => path.clone(),
        None => find_default_tendermint_path().chain(|| {
            (
                ErrorKind::InvalidInput,
                "Unable to find Tendermint folder in $TMHOME or $HOME",
            )
        })?,
    };

    let tendermint_genesis_config = fs::read_to_string(&tendermint_genesis_path).chain(|| {
        (
            ErrorKind::InvalidInput,
            "Something went wrong reading the Tendermint genesis file",
        )
    })?;
    let mut tendermint_genesis: serde_json::Value =
        serde_json::from_str(&tendermint_genesis_config).chain(|| {
            (
                ErrorKind::DeserializationError,
                "failed to parse Tendermint genesis file",
            )
        })?;

    let genesis_dev_config_string = fs::read_to_string(genesis_dev_config_path).chain(|| {
        (
            ErrorKind::InvalidInput,
            "Something went wrong reading the genesis dev config file",
        )
    })?;
    let genesis_dev_config: GenesisDevConfig = serde_json::from_str(&genesis_dev_config_string)
        .chain(|| {
            (
                ErrorKind::DeserializationError,
                "failed to parse genesis dev config",
            )
        })?;

    let genesis_time = Time::from_str(
        tendermint_genesis["genesis_time"]
            .as_str()
            .expect("genesis time config should be string"),
    )
    .expect("invalid genesis time format")
    .duration_since(Time::unix_epoch())
    .expect("invalid genesis time")
    .as_secs();
    let (app_hash, app_state, validators) =
        generate_genesis(&genesis_dev_config, genesis_time, unbonded_address)?;

    let app_hash = serde_json::to_value(app_hash).chain(|| {
        (
            ErrorKind::SerializationError,
            "failed to convert generated app hash into json value",
        )
    })?;
    let app_state = serde_json::to_value(app_state).chain(|| {
        (
            ErrorKind::SerializationError,
            "failed to convert generated app state into json value",
        )
    })?;
    let validators = serde_json::to_value(validators).chain(|| {
        (
            ErrorKind::SerializationError,
            "failed to convert generated validators into json value",
        )
    })?;
    tendermint_genesis["app_hash"] = app_hash;
    tendermint_genesis["app_state"] = app_state;
    tendermint_genesis["validators"] = validators;

    let tendermint_genesis_string =
        serde_json::to_string_pretty(&tendermint_genesis).chain(|| {
            (
                ErrorKind::InvalidInput,
                "Invalid generated Tendermint genesis",
            )
        })?;

    if in_place {
        if !no_backup {
            backup_tendermint_genesis(&tendermint_genesis_path)?;
        }
        write_tendermint_genesis(&tendermint_genesis_path, &tendermint_genesis_string)?;
    } else {
        println!("{}", tendermint_genesis_string);
    }

    Ok(())
}

fn find_default_tendermint_path() -> Option<PathBuf> {
    find_tendermint_path_from_tmhome().or_else(find_tendermint_path_from_home)
}

fn find_tendermint_path_from_tmhome() -> Option<PathBuf> {
    if let Ok(home) = env::var("TMHOME") {
        let path_buf = PathBuf::from(format!("{}/config/genesis.json", home));
        if path_buf.exists() {
            return Some(path_buf);
        }
    }

    None
}

fn find_tendermint_path_from_home() -> Option<PathBuf> {
    if let Ok(home) = env::var("HOME") {
        let path_buf = PathBuf::from(format!("{}/.tendermint/config/genesis.json", home));
        if path_buf.exists() {
            return Some(path_buf);
        }
    }

    None
}

pub fn generate_genesis(
    genesis_dev_config: &GenesisDevConfig,
    genesis_time: Timespec,
    unbonded_address: &Option<String>,
) -> Result<(String, InitConfig, Vec<TendermintValidator>)> {
    let mut dist: BTreeMap<RedeemAddress, (StakedStateDestination, Coin)> = BTreeMap::new();

    let unbonded_address = unbonded_address
        .as_ref()
        .map(|address| {
            RedeemAddress::from_str(address)
                .chain(|| (ErrorKind::InvalidInput, "Invalid unbonded address provided"))
        })
        .transpose()?;

    for (address, amount) in genesis_dev_config.distribution.iter() {
        let dest = if let Some(ref unbonded_address) = unbonded_address {
            if address == unbonded_address {
                StakedStateDestination::UnbondedFromGenesis
            } else {
                StakedStateDestination::Bonded
            }
        } else if genesis_dev_config.council_nodes.contains_key(&address) {
            StakedStateDestination::Bonded
        } else {
            StakedStateDestination::UnbondedFromGenesis
        };

        dist.insert(*address, (dest, *amount));
    }
    let constant_fee = Milli::from_str(&genesis_dev_config.initial_fee_policy.base_fee)
        .chain(|| (ErrorKind::InvalidInput, "Invalid constant fee"))?;
    let coefficient_fee = Milli::from_str(&genesis_dev_config.initial_fee_policy.per_byte_fee)
        .chain(|| (ErrorKind::InvalidInput, "Invalid per byte fee"))?;
    let fee_policy = LinearFee::new(constant_fee, coefficient_fee);
    let network_params = InitNetworkParameters {
        initial_fee_policy: fee_policy,
        required_council_node_stake: genesis_dev_config.required_council_node_stake,
        jailing_config: genesis_dev_config.jailing_config,
        slashing_config: genesis_dev_config.slashing_config,
        rewards_config: genesis_dev_config.rewards_config,
        max_validators: 50,
    };
    let config = InitConfig::new(
        dist,
        network_params,
        genesis_dev_config.council_nodes.clone(),
    );
    let genesis_app_hash = init_app_hash(&config, genesis_time);

    let validators = generate_validators(&genesis_dev_config)?;

    // app_hash, app_state
    Ok((encode_upper(genesis_app_hash), config, validators))
}

fn generate_validators(genesis_dev_config: &GenesisDevConfig) -> Result<Vec<TendermintValidator>> {
    let mut validators: Vec<TendermintValidator> = Vec::new();
    for (redeem_addr, (validator_name, _, validator_pubkey, _confidential_init)) in
        genesis_dev_config.council_nodes.iter()
    {
        let address = TendermintValidatorAddress::from(validator_pubkey);
        let power = genesis_dev_config
            .distribution
            .get(&redeem_addr)
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    format!(
                        "Council node {} does not have fund distribution",
                        redeem_addr
                    ),
                )
            })?;
        let power = TendermintVotePower::from(power.to_owned());

        let validator = TendermintValidator {
            address,
            name: validator_name.to_string(),
            power,
            pub_key: validator_pubkey.clone(),
        };

        validators.push(validator);
    }

    Ok(validators)
}

fn backup_tendermint_genesis(path: &PathBuf) -> Result<()> {
    fs::copy(
        &path,
        Path::new(&format!(
            "{}/genesis.bak.json",
            &path.parent().unwrap().display(),
        )),
    )
    .chain(|| {
        (
            ErrorKind::IoError,
            "failed to back up Tendermint genesis file",
        )
    })?;

    Ok(())
}

fn write_tendermint_genesis(path: &PathBuf, genesis_str: &str) -> Result<()> {
    File::create(&path)
        .chain(|| {
            (
                ErrorKind::IoError,
                "Failed to create Tendermint genesis.json",
            )
        })
        .and_then(|mut file| {
            file.write_all(genesis_str.as_bytes())
                .chain(|| (ErrorKind::IoError, "Failed to write Tenderint genesis file"))
        })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_dev_config_file() {
        let file = PathBuf::from("./example-dev-conf.json");
        let genesis_dev_config_string =
            fs::read_to_string(file).expect("can not find example-dev-config file");
        let genesis_dev_config: std::result::Result<GenesisDevConfig, _> =
            serde_json::from_str(&genesis_dev_config_string);
        assert!(genesis_dev_config.is_ok());
    }
}
