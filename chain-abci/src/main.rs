use log::info;
use std::net::{IpAddr, SocketAddr};
use std::thread;

use chain_abci::app::ChainNodeApp;
use chain_abci::enclave_bridge::EnclaveAppProxy;
use chain_abci::storage::*;
use chain_core::init::network::{get_network, get_network_id, init_chain_id};
use structopt::StructOpt;
use tx_validation_app::server::{TxValidationApp, TxValidationServer};

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
    #[structopt(short = "e", long = "enclave_storage", help = "Enclave storage path")]
    enclave_storage: String,
    #[structopt(
        short = "s",
        long = "enclave_server",
        help = "Validation enclave server bind address (e.g. ipc://enclave.socket or tcp://127.0.0.1:25933) for ZeroMQ."
    )]
    enclave_server: String,
    #[structopt(
        short = "tq",
        long = "tx_query",
        help = "Optional transaction query support for clients (tx query enclave listening address, e.g. mydomain.com:4444)"
    )]
    tx_query: Option<String>,
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
    let app = TxValidationApp::with_path(&opt.enclave_storage).expect("init validation app");
    let proxy = EnclaveAppProxy::new(app.clone());

    let enclave_server = opt.enclave_server.clone();
    let child_t = thread::spawn(move || {
        let mut server = TxValidationServer::new(&enclave_server, app.clone())
            .expect("could not start a zmq server");
        info!("starting zmq server");
        server.execute()
    });

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

    child_t.join().expect("server thread failed")
}
