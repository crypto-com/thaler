#![feature(const_string_new)]

mod enclave_u;

#[cfg(feature = "sgx-test")]
mod test;

use crate::enclave_u::init_connection;
use enclave_u::run_server;
use enclave_u_common::enclave_u::init_enclave;
use log::{error, info, warn};
use sgx_types::{c_int, sgx_status_t};
use sgx_urts::SgxEnclave;
use std::convert::TryInto;
use std::env;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

const TIMEOUT_SEC: c_int = 5;

pub fn start_enclave() -> SgxEnclave {
    match init_enclave(true) {
        Ok(r) => {
            info!("[+] Init Query Enclave Successful {}!", r.geteid());
            r
        }
        Err(e) => {
            panic!("[-] Init Query Enclave Failed {}!", e.as_str());
        }
    }
}

#[cfg(feature = "sgx-test")]
fn main() {
    test::test_integration();
}

#[cfg(not(feature = "sgx-test"))]
fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    let timeout = if let Some(x) = args.get(3) {
        x.parse::<c_int>().expect("valid timeout in seconds")
    } else {
        TIMEOUT_SEC
    };
    if args.len() < 3 {
        error!("Please provide the address:port to listen on (e.g. \"0.0.0.0:3443\") as the first argument and the ZMQ connection string (e.g. \"ipc://enclave.ipc\" or \"tcp://127.0.0.1:25933\") of the tx-validation server as the second");
        return;
    }
    init_connection(&args[2]);

    let enclave = start_enclave();

    info!("Running TX Decryption Query server...");
    let listener = TcpListener::bind(&args[1]).expect("failed to bind the TCP socket");
    // FIXME: thread pool + rate-limiting
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("new client connection");
                if timeout > 0 {
                    let utimeout = timeout.try_into().unwrap();
                    let _ = stream.set_read_timeout(Some(Duration::new(utimeout, 0)));
                    let _ = stream.set_write_timeout(Some(Duration::new(utimeout, 0)));
                }
                let mut retval = sgx_status_t::SGX_SUCCESS;
                let result = unsafe {
                    run_server(enclave.geteid(), &mut retval, stream.as_raw_fd(), timeout)
                };
                match result {
                    sgx_status_t::SGX_SUCCESS => {
                        info!("client query finished");
                    }
                    e => {
                        warn!("client query failed: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("connection failed: {}", e);
            }
        }
    }
}
