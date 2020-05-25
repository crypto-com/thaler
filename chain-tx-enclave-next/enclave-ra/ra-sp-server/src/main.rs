mod config;
mod context;
mod ias_client;
mod server;

use structopt::StructOpt;

use self::{config::SpRaConfig, server::SpRaServer};

fn main() {
    let config = SpRaConfig::from_args();
    env_logger::init();

    let address = config.address.clone();
    let server = SpRaServer::new(config).unwrap();
    server.run(address).unwrap();
}
