#[macro_use]
extern crate clap;
pub extern crate secp256k1zkp;
pub use secp256k1zkp as secp256k1;
extern crate blake2;
extern crate chain_core;
extern crate env_logger;
extern crate hex;
extern crate miscreant;
extern crate rand;
extern crate rpassword;
extern crate serde_cbor;
extern crate zeroize;

pub mod common;
mod keypair;
mod tx;
pub use common::{request_passphrase, Error, ExecResult, NONCE_SIZE};
pub mod storage;
use clap::{App, ArgMatches};
use keypair::keypair_cmd;
use std::path::Path;
use std::process::exit;
pub use storage::SimpleKeyStorage;
use tx::tx_cmd;

const DEFAULT_PATH: &str = ".signer";

/// Create new command executor
fn execute(matches: &ArgMatches) -> ExecResult {
    let path = Path::new(matches.value_of("base-path").unwrap_or(DEFAULT_PATH));
    let storage = SimpleKeyStorage::new(path.to_path_buf())?;
    match matches.subcommand() {
        ("keypair", Some(sub_m)) => keypair_cmd(sub_m, &storage),
        ("tx", Some(sub_m)) => tx_cmd(sub_m, &storage),
        _ => Err(Error::ExecError(
            "No command selected. Use `-h` for help".to_string(),
        )),
    }
}

fn main() {
    // TODO: implement Vault plugin?
    env_logger::init();
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    match execute(&matches) {
        Ok(_) => exit(0),
        Err(e) => {
            eprintln!("{}", e.to_string());
            exit(1)
        }
    };
}
