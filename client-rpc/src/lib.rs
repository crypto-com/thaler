mod rpc;
mod server;

use std::env;
use structopt::StructOpt;

use server::Server;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "client-rpc",
    about = "JSON-RPC server for wallet management and blockchain query"
)]
pub(crate) struct Options {
    #[structopt(
        name = "host",
        short,
        long,
        default_value = "0.0.0.0",
        help = "JSON-RPC server hostname"
    )]
    host: String,

    #[structopt(
        name = "port",
        short,
        long,
        default_value = "9981",
        help = "JSON-RPC server port"
    )]
    port: u16,

    #[structopt(
        name = "network-id",
        short,
        long,
        default_value = "00",
        help = "Network ID (Last two hex digits of chain-id)"
    )]
    network_id: String,

    #[structopt(
        name = "network-type",
        short = "i",
        long,
        default_value = "dev",
        help = "Network Type (main, test, dev)"
    )]
    network_type: String,

    #[structopt(
        name = "storage-dir",
        short,
        long,
        default_value = ".storage",
        help = "Local data storage directory"
    )]
    storage_dir: String,

    #[structopt(
        name = "tendermint-url",
        short,
        long,
        default_value = "http://localhost:26657/",
        help = "Url for connecting with tendermint RPC"
    )]
    tendermint_url: String,

    #[structopt(
        name = "websocket-url",
        short,
        long,
        default_value = "ws://localhost:26657/websocket",
        help = "Url for connecting with tendermint websocket RPC"
    )]
    websocket_url: String,
}

pub fn main() {
    env_logger::init();
    let options = Options::from_args();
    Server::new(options).unwrap().start().unwrap();
}

pub fn find_string(args: &[String], target: &str) -> Option<usize> {
    for i in 0..args.len() {
        if args[i] == target && i < args.len() - 1 {
            return Some(i);
        }
    }
    None
}
pub fn run() {
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
    if let Some(a) = find_string(&args, "--tendermint-url") {
        options.tendermint_url = args[a + 1].clone()
    }

    if let Some(a) = find_string(&args, "--websocket-url") {
        options.websocket_url = args[a + 1].clone()
    }

    log::info!("Options={:?}", options);
    Server::new(options).unwrap().start().unwrap();
}
