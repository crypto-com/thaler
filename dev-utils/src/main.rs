extern crate chain_core;
extern crate hex;

use chain_core::common::merkle::MerkleTree;
use chain_core::init::{
    coin::Coin,
    config::{ERC20Owner, InitConfig},
};
use chain_core::tx::data::{attribute::TxAttributes, Tx, TxId};
use std::env;

use hex::encode_upper;

/// generates genesis.json params -- TODO: more addresses
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 2 {
        let c = InitConfig::new(vec![ERC20Owner::new(args[1].parse().unwrap(), Coin::max())]);
        let hexid = hex::decode(&args[2]).unwrap()[0];

        let utxos = c.generate_utxos(&TxAttributes::new(hexid));
        let txids: Vec<TxId> = utxos.iter().map(Tx::id).collect();
        let tree = MerkleTree::new(&txids);
        let genesis_app_hash = tree.get_root_hash();
        println!("\"app_hash\": \"{}\",", encode_upper(genesis_app_hash));
        println!(
            "\"app_state\": {{\"distribution\":[{{\"address\":\"{}\",\"amount\":{} }}]}}",
            c.distribution[0].address, *c.distribution[0].amount
        );
        println!();
        println!("first tx: {:?}", utxos[0].id());
    }
}
