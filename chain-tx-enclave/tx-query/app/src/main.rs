#![feature(const_string_new)]

mod enclave_u;

#[cfg(feature = "sgx-test")]
mod test;

use crate::enclave_u::{init_connection, ZMQ_SOCKET};
use enclave_protocol::{EnclaveRequest, EnclaveResponse, FLAGS};
use enclave_u::run_server;
use enclave_u_common::enclave_u::{init_enclave, QUERY_TOKEN_KEY};
use log::{error, info, warn};
use parity_scale_codec::{Decode, Encode};
use sgx_types::sgx_status_t;
use sgx_urts::SgxEnclave;
use std::env;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

const TIMEOUT_SEC: u64 = 5;

pub fn start_enclave() -> SgxEnclave {
    ZMQ_SOCKET.with(|socket| {
        let q_token = QUERY_TOKEN_KEY.to_vec();
        let request = EnclaveRequest::GetCachedLaunchToken {
            enclave_metaname: q_token.clone(),
        };
        let req = request.encode();
        socket.send(req, FLAGS).expect("request sending failed");
        let msg = socket
            .recv_bytes(FLAGS)
            .expect("failed to receive a response");
        match EnclaveResponse::decode(&mut msg.as_slice()) {
            Ok(EnclaveResponse::GetCachedLaunchToken(Ok(token))) => {
                let launch_token = token.map(|x| x.to_vec());
                match init_enclave(true, launch_token) {
                    (Ok(r), new_token) => {
                        info!("[+] Init Enclave Successful {}!", r.geteid());
                        if let Some(launch_token) = new_token {
                            let request = EnclaveRequest::UpdateCachedLaunchToken {
                                enclave_metaname: q_token,
                                token: Box::new(launch_token),
                            };
                            let req = request.encode();
                            socket.send(req, FLAGS).expect("request sending failed");
                            socket
                                .recv_bytes(FLAGS)
                                .expect("failed to receive a response");
                        }
                        return r;
                    }
                    (Err(x), _) => {
                        panic!("[-] Init Enclave Failed {}!", x.as_str());
                    }
                };
            }
            _ => {
                panic!("error in launch zmq response");
            }
        }
    })
}

#[cfg(feature = "sgx-test")]
fn main() {
    test::test_integration();
}

#[cfg(not(feature = "sgx-test"))]
fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
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
                let _ = stream.set_read_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
                let _ = stream.set_write_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
                let mut retval = sgx_status_t::SGX_SUCCESS;
                let result =
                    unsafe { run_server(enclave.geteid(), &mut retval, stream.as_raw_fd()) };
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
