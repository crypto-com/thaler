use std::str::FromStr;

use failure::{format_err, Error, ResultExt};
use hex::{decode, encode_upper};
use structopt::StructOpt;

use chain_core::common::merkle::MerkleTree;
use chain_core::init::{address::RedeemAddress, coin::Coin, config::InitConfig};
use chain_core::tx::data::{attribute::TxAttributes, Tx, TxId};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, StructOpt)]
pub enum GenesisCommand {
    #[structopt(name = "generate", about = "Generate new genesis.json parameters")]
    Generate {
        #[structopt(
            name = "mapping_file_path",
            short,
            long,
            help = "Path to a file containing the ERC20 holdership; each line is of this format: 
            \"<ETH_ADDRESS> <INTEGER_AMOUNT_IN_BASE_UNITS>\" (i.e. 1 base unit == 0.00000001)"
        )]
        mapping_file_path: PathBuf,
        #[structopt(
            name = "chain-id",
            short,
            long,
            help = "Chain ID for transaction (Last two hex digits of chain-id)"
        )]
        chain_id: String,
        #[structopt(
            name = "launch_incentive_from",
            short = "f",
            long,
            help = "Secondary distribution and launch incentives address (the origin)"
        )]
        launch_incentive_from: String,
        #[structopt(
            name = "launch_incentive_to",
            short = "t",
            long,
            help = "Secondary distribution and launch incentives address (the destination)"
        )]
        launch_incentive_to: String,
        #[structopt(
            name = "long_term_incentive",
            short = "l",
            long,
            help = "Network long-term incentives address"
        )]
        long_term_incentive: String,
    },
}

impl GenesisCommand {
    pub fn execute(&self) -> Result<(), Error> {
        match self {
            GenesisCommand::Generate {
                mapping_file_path,
                chain_id,
                launch_incentive_from,
                launch_incentive_to,
                long_term_incentive,
            } => GenesisCommand::generate(
                &mapping_file_path,
                &launch_incentive_from,
                &launch_incentive_to,
                &long_term_incentive,
                &chain_id,
            ),
        }
    }

    fn generate(
        mapping_file_path: &PathBuf,
        launch_incentive_from: &str,
        launch_incentive_to: &str,
        long_term_incentive: &str,
        chain_id: &str,
    ) -> Result<(), Error> {
        let mapping_file = fs::read_to_string(mapping_file_path)
            .context(format_err!("Something went wrong reading the file"))?;
        let mut distribution = BTreeMap::new();
        for line in mapping_file.lines() {
            let mut l = line.split_whitespace();
            let address = RedeemAddress::from_str(l.next().expect("Missing address"))
                .context(format_err!("Invalid address"))?;
            let amount: u64 = l
                .next()
                .expect("Missing amount")
                .parse::<u64>()
                .context(format_err!("Invalid amount"))?;
            distribution.insert(
                address,
                Coin::new(amount).context(format_err!("Invalid amount"))?,
            );
        }
        let li_from_address = RedeemAddress::from_str(launch_incentive_from)
            .context(format_err!("Invalid address"))?;
        let li_to_address =
            RedeemAddress::from_str(launch_incentive_to).context(format_err!("Invalid address"))?;
        let lti_address =
            RedeemAddress::from_str(long_term_incentive).context(format_err!("Invalid address"))?;
        let config = InitConfig::new(distribution, li_from_address, li_to_address, lti_address);

        let chain_id = decode(chain_id).context(format_err!("Invalid chain-id"))?[0];

        let utxos = config.generate_utxos(&TxAttributes::new(chain_id));
        let txids: Vec<TxId> = utxos.iter().map(Tx::id).collect();
        let tree = MerkleTree::new(&txids);
        let genesis_app_hash = tree.get_root_hash();

        println!("\"app_hash\": \"{}\",", encode_upper(genesis_app_hash));
        let config_str = serde_json::to_string(&config).context(format_err!("Invalid config"))?;
        println!("\"app_state\": {}", config_str);
        println!();
        println!("first tx: {:?}", utxos[0].id());

        Ok(())
    }
}
