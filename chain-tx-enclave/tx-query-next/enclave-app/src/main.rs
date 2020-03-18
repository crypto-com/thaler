/// somehow this is needed with `cargo +nightly build --target=x86_64-fortanix-unknown-sgx`
extern crate enclave_protocol;

use enclave_protocol::ENCRYPTION_REQUEST_SIZE;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn main() -> std::io::Result<()> {
    // FIXME: this doesn't do yet anything interesting due to several missing pieces
    println!("enclave: connecting to zmq");
    let mut zmq_stream = TcpStream::connect("zmq")?;
    // currently, it's not possible to pass arguments
    // FIXME: fix that or bind via Usercall extensions?
    // ref: https://github.com/fortanix/rust-sgx/issues/136
    // ref: https://github.com/fortanix/rust-sgx/blob/master/examples/usercall-extension-bind/runner/src/main.rs#L26
    let listener = TcpListener::bind("0.0.0.0:3443")?;
    println!("enclave: listening");
    for stream in listener.incoming() {
        // FIXME: TLS https://github.com/crypto-com/chain/issues/860
        // (some deps -- probably to be done in / via app-runner)
        // attestation https://github.com/crypto-com/chain/issues/817
        // nonce in quotes: https://github.com/fortanix/rust-sgx/issues/116
        // unlinkable quotes: https://github.com/fortanix/rust-sgx/issues/113
        let mut from_connection = vec![0u8; ENCRYPTION_REQUEST_SIZE];
        let mut zmq_resp = vec![0u8; ENCRYPTION_REQUEST_SIZE];
        match stream {
            Ok(mut stream) => {
                println!("enclave: new connection");
                if let Ok(n) = stream.read(&mut from_connection) {
                    let _ = zmq_stream.write(&from_connection[..n]);
                    let _ = zmq_stream.flush();
                    if let Ok(m) = zmq_stream.read(&mut zmq_resp) {
                        let _ = stream.write(&zmq_resp[..m]);
                        let _ = stream.flush();
                    }
                }
            }
            Err(_) => {}
        }
    }
    Ok(())
}
