mod handler;

pub use rs_libc::alloc::*;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
};

use parity_scale_codec::{Decode, Encode};
use rustls::{NoClientAuth, ServerConfig, ServerSession, StreamOwned};
use thread_pool::ThreadPool;

use enclave_protocol::{
    DecryptionRequest, TxQueryInitRequest, TxQueryInitResponse, ENCRYPTION_REQUEST_SIZE,
};
use ra_enclave::{EnclaveRaConfig, EnclaveRaContext};

use self::handler::{
    get_random_challenge, handle_decryption_request, handle_encryption_request,
    verify_decryption_request,
};

pub fn entry() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    log::info!("Connecting to ZeroMQ");
    let zmq_stream = Arc::new(Mutex::new(TcpStream::connect("zmq")?));

    let num_threads = 4;
    let config = EnclaveRaConfig {
        sp_addr: "0.0.0.0:8989".to_string(),
        certificate_validity_secs: 86400,
    };

    let context = Arc::new(
        EnclaveRaContext::new(&config).expect("Unable to create new remote attestation context"),
    );

    log::info!("Successfully created remote attestation certificate!");
    log::info!("Starting TLS Server");

    let listener = TcpListener::bind("tx-query")?;

    let (thread_pool_sender, thread_pool) = ThreadPool::fixed_size(num_threads);

    for stream in listener.incoming() {
        let context = context.clone();
        let zmq_stream = zmq_stream.clone();

        thread_pool_sender
            .send(move || {
                let certificate = context
                    .get_certificate()
                    .expect("Unable to create remote attestation certificate");
                let mut tls_server_config = ServerConfig::new(NoClientAuth::new());
                certificate
                    .configure_server_config(&mut tls_server_config)
                    .expect("Unable to create TLS server config");
                tls_server_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];

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

fn handle_connection<T: Read + Write>(mut stream: T, zmq_stream: Arc<Mutex<TcpStream>>) {
    let mut bytes = vec![0u8; ENCRYPTION_REQUEST_SIZE];

    match stream.read(&mut bytes) {
        Ok(len) => {
            match TxQueryInitRequest::decode(&mut &bytes.as_slice()[0..len]) {
                Ok(TxQueryInitRequest::Encrypt(request)) => {
                    let response = handle_encryption_request(request, len, zmq_stream);

                    let response = match response {
                        Ok(response) => response,
                        Err(message) => {
                            log::error!("Error while handling encryption request: {}", message);
                            return;
                        }
                    };

                    if let Err(err) = stream.write_all(&response.encode()) {
                        log::error!(
                            "Error while writing encryption response back to TLS stream: {}",
                            err
                        );
                    }
                }
                Ok(TxQueryInitRequest::DecryptChallenge) => {
                    let challenge = get_random_challenge();

                    if let Err(err) =
                        stream.write_all(&TxQueryInitResponse::DecryptChallenge(challenge).encode())
                    {
                        log::error!("Unable to write random challenge to TLS stream: {}", err);
                        return;
                    }

                    match stream.read(&mut bytes) {
                        Ok(len) => {
                            match DecryptionRequest::decode(&mut &bytes.as_slice()[0..len]) {
                                Ok(decryption_request) => {
                                    if !verify_decryption_request(&decryption_request, challenge) {
                                        log::error!("Decryption request is invalid");
                                        return;
                                    }

                                    match handle_decryption_request(&decryption_request, zmq_stream)
                                    {
                                        Ok(decryption_response) => {
                                            if let Err(err) =
                                                stream.write_all(&decryption_response.encode())
                                            {
                                                log::error!("Error while writing decryption response back to TLS stream: {}", err);
                                            }
                                        }
                                        Err(err) => log::error!(
                                            "Error while handling decryption request: {}",
                                            err
                                        ),
                                    }
                                }
                                Err(err) => {
                                    log::error!("Unable to decode decryption request: {}", err)
                                }
                            }
                        }
                        Err(err) => {
                            log::error!(
                                "Unable to read challenge response from TLS stream: {}",
                                err
                            );
                        }
                    }
                }
                Err(err) => {
                    log::error!("Error while decoding tx-query init request: {}", err);
                }
            };
        }
        Err(err) => log::error!("Error while reading bytes from TLS stream: {}", err),
    }
}
