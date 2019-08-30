mod rpc;
mod server;

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

fn main() {
    env_logger::init();
    let options = Options::from_args();
    Server::new(options).unwrap().start().unwrap();
}
