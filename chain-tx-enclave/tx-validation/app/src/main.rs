mod enclave_u;
mod server;
#[cfg(feature = "sgx-test")]
mod test;

use crate::enclave_u::{get_token, store_token};
use crate::server::TxValidationServer;
use enclave_u_common::enclave_u::{init_enclave, VALIDATION_TOKEN_KEY};
use enclave_u_common::{storage_path, META_KEYSPACE, TX_KEYSPACE};
use log::{error, info};
use sled::Db;
use std::env;
use std::thread;

#[cfg(feature = "sgx-test")]
fn main() {
    test::test_sealing();
}

#[cfg(not(feature = "sgx-test"))]
fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        error!("Please provide the ZMQ connection string (e.g. \"tcp://127.0.0.1:25933\") as the first argument");
        return;
    }
    let db = Db::open(storage_path()).expect("failed to open a storage path");
    let mut metadb = db
        .open_tree(META_KEYSPACE)
        .expect("failed to open a meta keyspace");
    let txdb = db
        .open_tree(TX_KEYSPACE)
        .expect("failed to open a tx keyspace");
    let token = get_token(&metadb, VALIDATION_TOKEN_KEY);
    let enclave = match init_enclave(true, token) {
        (Ok(r), new_token) => {
            info!("[+] Init Enclave Successful {}!", r.geteid());
            if let Some(launch_token) = new_token {
                let _ = store_token(&mut metadb, VALIDATION_TOKEN_KEY, launch_token.to_vec());
            }
            r
        }
        (Err(x), _) => {
            error!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    let child_t = thread::spawn(move || {
        let mut server = TxValidationServer::new(&args[1], enclave, txdb, metadb)
            .expect("could not start a zmq server");
        info!("starting zmq server");
        server.execute()
    });
    child_t.join().expect("server thread failed");
}
