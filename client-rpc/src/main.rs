mod server;
mod wallet_rpc;

use structopt::StructOpt;

use server::Server;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "client-rpc",
    about = "JSON-RPC server for wallet management and blockchain query"
)]
struct Opt {
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
        name = "chain-id",
        short,
        long,
        help = "Chain ID (Last two hex digits of chain-id)"
    )]
    chain_id: String,
}

fn main() {
    let opt = Opt::from_args();

    Server::new(&opt.host[..], opt.port, &opt.chain_id[..])
        .unwrap()
        .start()
        .unwrap();
}
