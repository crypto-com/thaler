use log::info;
use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use chain_abci::app::ChainNodeApp;
#[cfg(any(feature = "mock-enclave", not(target_os = "linux")))]
use chain_abci::enclave_bridge::mock::MockClient;
#[cfg(all(not(feature = "mock-enclave"), target_os = "linux"))]
use chain_abci::enclave_bridge::real::TxValidationApp;
use chain_core::init::network::{get_network, get_network_id, init_chain_id};
use chain_storage::{Storage, StorageConfig, StorageType};
#[cfg(any(feature = "mock-enclave", not(target_os = "linux")))]
use log::warn;
use serde::Deserialize;
use std::io::BufReader;
use structopt::StructOpt;

#[derive(Deserialize, Debug)]
pub struct Config {
    port: u16,
    host: String,
    genesis_app_hash: Option<String>,
    chain_id: Option<String>,
    enclave_server: Option<String>,
    tx_query: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 26658,
            host: "127.0.0.1".into(),
            genesis_app_hash: None,
            chain_id: None,
            enclave_server: None,
            tx_query: None,
        }
    }
}

impl Config {
    pub fn from_file(path: &Path) -> Self {
        let file =
            File::open(path).unwrap_or_else(|_| panic!("can not open config file {:?}", path));
        let reader = BufReader::new(file);
        serde_yaml::from_reader(reader).expect("invalid config")
    }
    pub fn update(&mut self, opt: &AbciOpt) {
        if opt.host.is_some() {
            self.host = opt.host.clone().unwrap();
        }
        if opt.port.is_some() {
            self.port = opt.port.unwrap();
        }
        if opt.genesis_app_hash.is_some() {
            self.genesis_app_hash = opt.genesis_app_hash.clone();
        }
        if opt.chain_id.is_some() {
            self.chain_id = opt.chain_id.clone();
        }
        if opt.enclave_server.is_some() {
            self.enclave_server = opt.enclave_server.clone();
        }
        if opt.tx_query.is_some() {
            self.tx_query = opt.tx_query.clone();
        }
    }
    pub fn is_valid(&self) -> bool {
        let mut valid = true;
        if self.genesis_app_hash.is_none() {
            log::error!("genesis_app_hash should be set");
            valid = false
        }
        if self.chain_id.is_none() {
            log::error!("chain_id should be set");
            valid = false
        }
        if self.enclave_server.is_none() {
            log::error!("enclave_server should be set");
            valid = false
        }
        valid
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "chain-abci",
    about = " Pre-alpha version prototype of Crypto.com Chain node (Tendermint ABCI application)."
)]
pub struct AbciOpt {
    #[structopt(
        short = "d",
        long = "data",
        default_value = ".cro-storage/",
        help = "Sets a data storage directory"
    )]
    data: String,
    #[structopt(long = "config", help = "Sets a config file path")]
    config: Option<PathBuf>,
    #[structopt(short = "p", long = "port", help = "Sets a port to listen on")]
    port: Option<u16>,
    #[structopt(short = "h", long = "host", help = "Sets the ip address to listen on")]
    host: Option<String>,
    #[structopt(
        short = "g",
        long = "genesis_app_hash",
        help = "The expected app hash after init chain (computed from the merkle trie root etc.)"
    )]
    genesis_app_hash: Option<String>,
    #[structopt(
        short = "c",
        long = "chain_id",
        help = "The expected chain id from init chain (the name convention is \"...some-name...-<TWO_HEX_DIGITS>\")"
    )]
    chain_id: Option<String>,
    #[structopt(
        short = "e",
        long = "enclave_server",
        help = "Connection string (e.g. ipc://enclave.socket or tcp://127.0.0.1:25933) on which ZeroMQ server wrapper around the transaction validation enclave will listen."
    )]
    enclave_server: Option<String>,
    #[structopt(
        short = "tq",
        long = "tx_query",
        help = "Optional transaction query support for clients (tx query enclave listening address, e.g. mydomain.com:4444)"
    )]
    tx_query: Option<String>,
}

/// normal
#[cfg(all(not(feature = "mock-enclave"), target_os = "linux"))]
fn get_enclave_proxy() -> TxValidationApp {
    TxValidationApp::default()
}

/// for development
#[cfg(any(feature = "mock-enclave", not(target_os = "linux")))]
fn get_enclave_proxy() -> MockClient {
    warn!("Using mock (non-enclave) infrastructure");
    MockClient::new(get_network_id())
}

#[cfg(feature = "sgx-test")]
fn main() {
    // Teaclave SGX SDK doesn't work with Rust unit testing facility
    chain_abci::enclave_bridge::real::test::test_sealing();
}

#[cfg(not(feature = "sgx-test"))]
fn main() {
    env_logger::init();
    let opt = AbciOpt::from_args();
    // if the config file not set, we use DATA_PATH/config.yaml as default
    let mut default_config_file = PathBuf::from(&opt.data);
    default_config_file.push("config.yaml");
    let config_file = opt.config.clone().unwrap_or(default_config_file);
    let mut config = if config_file.exists() {
        Config::from_file(config_file.as_path())
    } else {
        Config::default()
    };
    config.update(&opt);
    if !config.is_valid() {
        return;
    }

    init_chain_id(&config.chain_id.clone().unwrap());
    info!(
        "network={:?} network_id={:X}",
        get_network(),
        get_network_id()
    );
    let tx_validator = get_enclave_proxy();

    let host = config.host.parse().expect("invalid host");
    let addr = SocketAddr::new(host, config.port);
    let storage = Storage::new(&StorageConfig::new(&opt.data, StorageType::Node));
    info!("starting up");
    abci::run(
        addr,
        ChainNodeApp::new_with_storage(
            tx_validator,
            &config.genesis_app_hash.unwrap(),
            &config.chain_id.unwrap(),
            storage,
            config.tx_query,
            config.enclave_server,
        ),
    );
}
