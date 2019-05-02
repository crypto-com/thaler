use std::str::FromStr;

use failure::{format_err, Error, ResultExt};
use hex::{decode, encode_upper};
use structopt::StructOpt;

use chain_core::common::merkle::MerkleTree;
use chain_core::init::{
    address::RedeemAddress,
    coin::Coin,
    config::{ERC20Owner, InitConfig},
};
use chain_core::tx::data::{attribute::TxAttributes, Tx, TxId};

#[derive(Debug, StructOpt)]
pub enum GenesisCommand {
    #[structopt(name = "generate", about = "Generate new genesis.json parameters")]
    Generate {
        #[structopt(name = "address", short, long, help = "Address of genesis block")]
        address: String,
        #[structopt(
            name = "chain-id",
            short,
            long,
            help = "Chain ID for transaction (Last two hex digits of chain-id)"
        )]
        chain_id: String,
    },
}

impl GenesisCommand {
    pub fn execute(&self) -> Result<(), Error> {
        match self {
            GenesisCommand::Generate { address, chain_id } => {
                GenesisCommand::generate(&address, &chain_id)
            }
        }
    }

    fn generate(address: &str, chain_id: &str) -> Result<(), Error> {
        let config = InitConfig::new(vec![ERC20Owner::new(
            RedeemAddress::from_str(address).context(format_err!("Invalid address"))?,
            Coin::max(),
        )]);
        let chain_id = decode(chain_id).context(format_err!("Invalid chain-id"))?[0];

        let utxos = config.generate_utxos(&TxAttributes::new(chain_id));
        let txids: Vec<TxId> = utxos.iter().map(Tx::id).collect();
        let tree = MerkleTree::new(&txids);
        let genesis_app_hash = tree.get_root_hash();

        println!("\"app_hash\": \"{}\",", encode_upper(genesis_app_hash));
        println!(
            "\"app_state\": {{\"distribution\":[{{\"address\":\"{}\",\"amount\":{} }}]}}",
            config.distribution[0].address,
            u64::from(config.distribution[0].amount)
        );
        println!();
        println!("first tx: {:?}", utxos[0].id());

        Ok(())
    }
}
