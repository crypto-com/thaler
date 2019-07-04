mod app;
mod enclave_bridge;
mod storage;

use clap::load_yaml;
use clap::App;
use log::info;
use std::net::SocketAddr;
use zmq::{Context, REQ};

use crate::app::ChainNodeApp;
use crate::enclave_bridge::ZmqEnclaveClient;
use crate::storage::*;

fn main() {
    // TODO
    env_logger::init();
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let ctx = Context::new();
    let socket = ctx.socket(REQ).expect("failed to init zmq context");
    let enclave_conn = matches
        .value_of("enclave_server")
        .unwrap_or("tcp://127.0.0.1:25933");
    socket
        .connect(enclave_conn)
        .expect("failed to connect to enclave zmq wrapper");
    let proxy = ZmqEnclaveClient::new(socket);
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
            proxy,
            &genesis_app_hash,
            &chain_id,
            &StorageConfig::new(data, StorageType::Node),
            &StorageConfig::new(data, StorageType::AccountTrie),
        ),
    );
}
