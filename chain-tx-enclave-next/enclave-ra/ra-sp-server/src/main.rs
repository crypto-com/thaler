mod config;
mod context;
mod ias_client;
mod server;

use structopt::StructOpt;

use self::{config::SpRaConfig, server::SpRaServer};

fn main() {
    let config = SpRaConfig::from_args();
    env_logger::init();

    let mut attempt = 0;
    while attempt < 3 {
        let config = SpRaConfig::from_args();
        let address = config.address.clone();
        if let Ok(server) = SpRaServer::new(config) {
            server.run(address).unwrap();
        } else {
            attempt += 1;
            std::thread::sleep(std::time::Duration::from_millis(10000));
        }
    }
    panic!("failed to init SpRaServer");
}
