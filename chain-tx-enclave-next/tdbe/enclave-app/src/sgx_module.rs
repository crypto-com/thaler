mod handler;

pub use rs_libc::alloc::*;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
};

use parity_scale_codec::{Decode, Encode};
use rustls::{ServerSession, StreamOwned};
use thread_pool::ThreadPool;

use enclave_protocol::tdbe_protocol::{TdbeRequest, TdbeResponse, TDBE_REQUEST_SIZE};
use ra_client::EnclaveCertVerifier;
use ra_enclave::{EnclaveRaConfig, EnclaveRaContext};

use self::handler::{get_key_package, get_spent_transaction_outputs};

pub fn entry() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    log::info!("Connecting to ZeroMQ");
    let zmq_stream = Arc::new(Mutex::new(TcpStream::connect("zmq")?));

    let num_threads = 4;
    let config = EnclaveRaConfig {
        sp_addr: "ra-sp-server".to_string(),
        certificate_validity_secs: 86400,
    };

    let context = Arc::new(
        EnclaveRaContext::new(&config).expect("Unable to create new remote attestation context"),
    );

    log::info!("Successfully created remote attestation certificate!");
    log::info!("Starting TLS Server");

    let listener = TcpListener::bind("tdbe")?;

    let (thread_pool_sender, thread_pool) = ThreadPool::fixed_size(num_threads);

    for stream in listener.incoming() {
        let context = context.clone();
        let zmq_stream = zmq_stream.clone();

        thread_pool_sender
            .send(move || {
                let certificate = context
                    .get_certificate()
                    .expect("Unable to create remote attestation certificate");
                let verifier = EnclaveCertVerifier::default();
                let mut tls_server_config = verifier.into_server_config();
                certificate
                    .configure_server_config(&mut tls_server_config)
                    .expect("Unable to create TLS server config");

                let tls_server_config = Arc::new(tls_server_config);

                let tls_session = ServerSession::new(&tls_server_config);
                let stream = StreamOwned::new(tls_session, stream.unwrap());

                handle_connection(stream, zmq_stream);
            })
            .expect("Unable to send tasks to thread pool");
    }

    thread_pool.shutdown();
    Ok(())
}

fn handle_connection<T: Read + Write>(mut stream: T, _zmq_stream: Arc<Mutex<TcpStream>>) {
    let mut bytes = vec![0u8; TDBE_REQUEST_SIZE];

    while let Ok(len) = stream.read(&mut bytes) {
        let response = match TdbeRequest::decode(&mut &bytes.as_slice()[0..len]) {
            Err(e) => TdbeResponse::Error {
                message: format!("Unable to deserialize TDBE request: {}", e),
            },
            Ok(TdbeRequest::GetSpentTransactionOutputs { txids }) => {
                match get_spent_transaction_outputs(txids) {
                    Ok(spent_utxos) => TdbeResponse::GetSpentTransactionOutputs { spent_utxos },
                    Err(message) => TdbeResponse::Error { message },
                }
            }
            Ok(TdbeRequest::GetKeyPackage) => match get_key_package() {
                Ok(key_package) => TdbeResponse::GetKeyPackage { key_package },
                Err(message) => TdbeResponse::Error { message },
            },
        };

        if let Err(err) = stream.write_all(&response.encode()) {
            log::error!("Error while writing TDBE response to TLS stream: {}", err);
            return;
        }
    }
}
