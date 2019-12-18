use log::info;
use std::net::{IpAddr, SocketAddr};
#[cfg(not(feature = "mock-validation"))]
use zmq::{Context, REQ};

use chain_abci::app::ChainNodeApp;
#[cfg(feature = "mock-validation")]
use chain_abci::enclave_bridge::mock::MockClient;
#[cfg(not(feature = "mock-validation"))]
use chain_abci::enclave_bridge::ZmqEnclaveClient;
use chain_abci::storage::*;
use chain_core::init::network::{get_network, get_network_id, init_chain_id};
#[cfg(feature = "mock-validation")]
use log::warn;
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
    #[structopt(
        short = "tq",
        long = "tx_query",
        help = "Optional transaction query support for clients (tx query enclave listening address, e.g. mydomain.com:4444)"
    )]
    tx_query: Option<String>,
}

/// normal
#[cfg(not(feature = "mock-validation"))]
fn get_enclave_proxy(opts: &AbciOpt) -> ZmqEnclaveClient {
    let ctx = Context::new();
    let socket = ctx.socket(REQ).expect("failed to init zmq context");
    socket
        .connect(&opts.enclave_server)
        .expect("failed to connect to enclave zmq wrapper");
    ZmqEnclaveClient::new(socket)
}

/// for development
#[cfg(feature = "mock-validation")]
fn get_enclave_proxy(_opts: &AbciOpt) -> MockClient {
    warn!("Using mock (non-enclave) infrastructure");
    MockClient::new(get_network_id())
}

fn main() {
    env_logger::init();
    let opt = AbciOpt::from_args();
    init_chain_id(&opt.chain_id);
    info!(
        "network={:?} network_id={:X}",
        get_network(),
        get_network_id()
    );
    let proxy = get_enclave_proxy(&opt);

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
            opt.tx_query,
        ),
    );
}
