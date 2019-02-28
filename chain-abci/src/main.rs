mod app;
mod storage;

use clap::load_yaml;
use clap::App;
use log::info;
use std::net::SocketAddr;

use crate::app::ChainNodeApp;
use crate::storage::*;

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
