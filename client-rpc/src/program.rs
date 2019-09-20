use structopt::StructOpt;

use crate::server::Server;
use std::env;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "client-rpc",
    about = "JSON-RPC server for wallet management and blockchain query"
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

    #[structopt(
        name = "network-id",
        short,
        long,
        default_value = "00",
        help = "Network ID (Last two hex digits of chain-id)"
    )]
    pub network_id: String,

    #[structopt(
        name = "network-type",
        short = "i",
        long,
        default_value = "dev",
        help = "Network Type (main, test, dev)"
    )]
    pub network_type: String,

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
    // "~/Electron", ".", "--network-id", "ab", "--network-type", "test"]
    let args: Vec<String> = env::args().collect();
    log::info!("args={:?}", args);
    let mut options = Options::from_iter(vec![""].iter());
    if let Some(a) = find_string(&args, "--network-id") {
        options.network_id = args[a + 1].clone()
    }

    if let Some(a) = find_string(&args, "--network-type") {
        options.network_type = args[a + 1].clone()
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
