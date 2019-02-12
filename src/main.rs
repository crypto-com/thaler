mod app;
mod storage;

extern crate abci;
extern crate bit_vec;
#[macro_use]
extern crate log;
extern crate blake2;
extern crate chain_core;
extern crate env_logger;
extern crate ethbloom;
extern crate hex;
extern crate integer_encoding;
extern crate kvdb;
extern crate kvdb_rocksdb;
extern crate protobuf;
pub extern crate secp256k1zkp;
pub use secp256k1zkp as secp256k1;
extern crate serde;
extern crate serde_cbor;
extern crate serde_json;
#[macro_use]
extern crate clap;
extern crate kvdb_memorydb;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;

use app::ChainNodeApp;
use clap::App;
use std::net::SocketAddr;
use storage::*;

fn main() {
    // TODO
    env_logger::init();
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let data = matches.value_of("data").unwrap_or(".cro-storage/");
    let port = matches.value_of("port").unwrap_or("26658");
    let host = matches.value_of("host").unwrap_or("127.0.0.1");
    let genesis_app_hash = matches.value_of("genesis_app_hash").unwrap();
    let chain_id = matches.value_of("chain_id").unwrap();

    let addr = SocketAddr::new(host.parse().unwrap(), port.parse().unwrap());
    info!("starting up");
    abci::run(
        addr,
        ChainNodeApp::new(
            &genesis_app_hash,
            &chain_id,
            &StorageConfig { db_path: data },
        ),
    );
}
