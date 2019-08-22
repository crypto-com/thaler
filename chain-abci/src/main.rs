mod app;
mod enclave_bridge;
mod storage;

use log::info;
use std::net::{IpAddr, SocketAddr};
use zmq::{Context, REQ};

use crate::app::ChainNodeApp;
use crate::enclave_bridge::ZmqEnclaveClient;
use crate::storage::*;
use chain_core::init::network::{get_network, get_network_id, init_chain_id};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "chain-abci",
    about = " Pre-alpha version prototype of Crypto.com Chain node (Tendermint ABCI application)."
)]
struct AbciOpt {
    #[structopt(
        short = "d",
        long = "data",
        default_value = ".cro-storage/",
        help = "Sets a data storage directory"
    )]
    data: String,
    #[structopt(
        short = "p",
        long = "port",
        default_value = "26658",
        help = "Sets a port to listen on"
    )]
    port: u16,
    #[structopt(
        short = "h",
        long = "host",
        default_value = "127.0.0.1",
        help = "Sets the ip address to listen on"
    )]
    host: IpAddr,
    #[structopt(
        short = "g",
        long = "genesis_app_hash",
        help = "The expected app hash after init chain (computed from the merkle trie root etc.)"
    )]
    genesis_app_hash: String,
    #[structopt(
        short = "c",
        long = "chain_id",
        help = "The expected chain id from init chain (the name convention is \"...some-name...-<TWO_HEX_DIGITS>\")"
    )]
    chain_id: String,
    #[structopt(
        short = "e",
        long = "enclave_server",
        help = "Connection string (e.g. ipc://enclave.socket or tcp://127.0.0.1:25933) for ZeroMQ server wrapper around the transaction validation enclave."
    )]
    enclave_server: String,
}

fn main() {
    env_logger::init();
    let opt = AbciOpt::from_args();
    let ctx = Context::new();
    let socket = ctx.socket(REQ).expect("failed to init zmq context");
    socket
        .connect(&opt.enclave_server)
        .expect("failed to connect to enclave zmq wrapper");
    let proxy = ZmqEnclaveClient::new(socket);

    init_chain_id(&opt.chain_id);
    info!(
        "network={:?} network_id={:X}",
        get_network(),
        get_network_id()
    );

    let addr = SocketAddr::new(opt.host, opt.port);
    info!("starting up");
    abci::run(
        addr,
        ChainNodeApp::new(
            proxy,
            &opt.genesis_app_hash,
            &opt.chain_id,
            &StorageConfig::new(&opt.data, StorageType::Node),
            &StorageConfig::new(&opt.data, StorageType::AccountTrie),
        ),
    );
}
