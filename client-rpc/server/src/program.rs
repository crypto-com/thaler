use structopt::StructOpt;

use crate::server::Server;
use std::env;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "client-rpc",
    about = r#"JSON-RPC server for wallet management and blockchain query
ENVIRONMENT VARIABLES:
    CRYPTO_GENESIS_FINGERPRINT             Set the genesis fingerprint(Optional)
    "#
)]
pub struct Options {
    #[structopt(
        name = "host",
        short,
        long,
        default_value = "0.0.0.0",
        help = "JSON-RPC server hostname"
    )]
    pub host: String,

    #[structopt(
        name = "port",
        short,
        long,
        default_value = "9981",
        help = "JSON-RPC server port"
    )]
    pub port: u16,

    #[structopt(name = "chain-id", short, long, help = "Full chain ID")]
    pub chain_id: String,

    #[structopt(
        name = "storage-dir",
        short,
        long,
        default_value = ".storage",
        help = "Local data storage directory"
    )]
    pub storage_dir: String,

    #[structopt(
        name = "websocket-url",
        short,
        long,
        default_value = "ws://localhost:26657/websocket",
        help = "Url for connecting with tendermint websocket RPC"
    )]
    pub websocket_url: String,
    #[structopt(
        name = "enable-fast-forward",
        long,
        help = "Enable fast forward when syncing wallet, which is not secure when connecting to outside nodes"
    )]
    pub enable_fast_forward: bool,
    #[structopt(
        name = "disable-light-client",
        long,
        help = "Disable light client, which is not secure when connecting to outside nodes"
    )]
    pub disable_light_client: bool,
    #[structopt(
        name = "disable-address-recovery",
        long,
        help = "Disable address recovery when syncing wallet, which is not necessary, when addresses already exist"
    )]
    pub disable_address_recovery: bool,
    #[structopt(
        name = "batch-size",
        short,
        long,
        default_value = "20",
        help = "Number of requests per batch when syncing wallet"
    )]
    pub batch_size: usize,
    #[structopt(
        name = "block-height-ensure",
        long,
        default_value = "50",
        help = "Number of block height to rollback the utxos in the pending transactions"
    )]
    pub block_height_ensure: u64,
}

#[allow(dead_code)]
pub fn run_cli() {
    env_logger::init();
    let options = Options::from_args();
    Server::new(options).unwrap().start().unwrap();
}

#[allow(dead_code)]
pub fn find_string(args: &[String], target: &str) -> Option<usize> {
    for i in 0..args.len() {
        if args[i] == target && i < args.len() - 1 {
            return Some(i);
        }
    }
    None
}

#[allow(dead_code)]
pub fn run_electron() {
    env_logger::init();
    // "~/Electron", ".", "--chain-id", "ab"]
    let args: Vec<String> = env::args().collect();
    log::info!("args={:?}", args);
    let mut options = Options::from_iter(vec![""].iter());
    if let Some(a) = find_string(&args, "--chain-id") {
        options.chain_id = args[a + 1].clone()
    }
    if let Some(a) = find_string(&args, "--storage-dir") {
        options.storage_dir = args[a + 1].clone()
    }

    if let Some(a) = find_string(&args, "--websocket-url") {
        options.websocket_url = args[a + 1].clone()
    }

    let mut storage = dirs::data_dir().expect("get storage dir");
    storage.push(".cro_storage");
    options.storage_dir = storage.to_str().expect("get storage dir to_str").into();

    log::info!("Options={:?}", options);
    log::info!("Storage={}", options.storage_dir);
    Server::new(options).unwrap().start().unwrap();
}
