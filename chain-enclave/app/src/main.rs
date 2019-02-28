extern crate zmq;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate hex;
extern crate abci_enclave_protocol;

mod server;
mod enclave_u;

use std::thread;
use std::env;
use crate::server::TxValidationServer;
use crate::enclave_u::init_enclave;

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };

    let args: Vec<String> = env::args().collect();

    let child_t = thread::spawn(move || {
        let mut server = TxValidationServer::new(&args[1], enclave).expect("could not start a zmq server");
        server.execute()
    });
    child_t.join().expect("server thread failed");
}