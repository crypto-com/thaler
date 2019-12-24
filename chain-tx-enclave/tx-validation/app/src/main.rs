extern crate tx_validation_app;

#[cfg(feature = "sgx-test")]
mod test;

use enclave_u_common::storage_path;
use log::{error, info};
use std::env;
use std::thread;
use tx_validation_app::server::{TxValidationApp, TxValidationServer};

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
    let child_t = thread::spawn(move || {
        let app = TxValidationApp::with_path(&storage_path()).expect("init validation app");
        let mut server = TxValidationServer::new(&args[1], app).expect("start validation server");
        info!("starting zmq server");
        server.execute()
    });
    child_t.join().expect("server thread failed");
}
