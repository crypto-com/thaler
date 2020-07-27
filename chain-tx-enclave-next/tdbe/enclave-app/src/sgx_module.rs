mod handler;

pub use rs_libc::alloc::*;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
};

use chrono::Duration;
use rustls::{ClientSession, ServerSession, StreamOwned};
use sgx_isa::Report;
use thread_pool::ThreadPool;
use webpki::DNSNameRef;

use chain_core::tx::data::TxId;
use enclave_protocol::{
    codec::{StreamRead, StreamWrite},
    tdbe_protocol::{TrustedTdbeRequest, TrustedTdbeResponse},
};
use ra_client::{EnclaveCertVerifier, EnclaveCertVerifierConfig, EnclaveInfo};
use ra_enclave::{EnclaveRaConfig, EnclaveRaContext, DEFAULT_EXPIRATION_SECS};
use tdbe_common::TdbeConfig;

const THREAD_POOL_SIZE: usize = 4;

pub fn entry() -> std::io::Result<()> {
    // Initialize logger
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    // Get enclave certificate verifier
    let verifier = get_enclave_verifier();

    // Get initial options provided in command line arguments
    let tdbe_config = get_tdbe_config();

    // Create remote attestation context
    let context = create_ra_context();

    // Fetch initial transaction data if TDBE is configured to connect to another TDBE server
    if let Some(ref tdbe_dns_name) = tdbe_config.tdbe_dns_name {
        if let Err(err) = fetch_initial_data(
            &context,
            verifier.clone(),
            tdbe_dns_name,
            &tdbe_config.transaction_ids,
        ) {
            log::error!("Unable to fetch initial data from another TDBE server");
            return Err(err);
        }
    }

    // Connect to ZeroMQ
    log::info!("Connecting to ZeroMQ");
    let zmq_stream = Arc::new(Mutex::new(TcpStream::connect("zmq")?));

    // Start TDBE server
    log::info!("Starting TBDE Server");
    let listener = TcpListener::bind("tdbe")?;

    // Create a thread pool for handling incoming connections
    let (thread_pool_sender, thread_pool) = ThreadPool::fixed_size(THREAD_POOL_SIZE);

    for stream in listener.incoming() {
        let context = context.clone();
        let verifier = verifier.clone();
        let zmq_stream = zmq_stream.clone();

        thread_pool_sender
            .send(move || {
                // Create TLS stream
                let tls_stream = create_tls_server_stream(
                    &context,
                    verifier,
                    stream.expect("Error while conntecting to incoming stream"),
                )
                .expect("Unable to create TLS server stream");

                // Handle client conntection
                handle_connection(tls_stream, zmq_stream);
            })
            .expect("Unable to send tasks to thread pool");
    }

    // Shut down thread pool when the listener is closed
    thread_pool.shutdown();

    Ok(())
}

fn handle_connection<T: Read + Write>(mut stream: T, zmq_stream: Arc<Mutex<TcpStream>>) {
    loop {
        match TrustedTdbeRequest::read_from(&mut stream) {
            Ok(tdbe_request) => {
                let tdbe_response = match tdbe_request {
                    TrustedTdbeRequest::GetTransactionsWithOutputs { transaction_ids } => {
                        match handler::get_transactions_with_outputs(
                            transaction_ids.into_owned(),
                            &mut zmq_stream.lock().unwrap(),
                        ) {
                            Ok(transactions) => {
                                TrustedTdbeResponse::GetTransactionsWithOutputs { transactions }
                            }
                            Err(message) => TrustedTdbeResponse::Error {
                                message: message.into(),
                            },
                        }
                    }
                };

                if let Err(err) = tdbe_response.write_to(&mut stream) {
                    log::error!("Error while writing response to TLS stream: {}", err);
                    break;
                }
            }
            Err(err) => {
                log::error!("Error while reading bytes from TLS stream: {}", err);
                break;
            }
        }
    }
}

fn get_enclave_verifier() -> EnclaveCertVerifier {
    log::info!("Creating enclave certificate verifier");

    let enclave_info = EnclaveInfo::from_report(Report::for_self(), None);
    let verifier_config = EnclaveCertVerifierConfig::new_with_enclave_info(enclave_info);
    let verifier = EnclaveCertVerifier::new(verifier_config)
        .expect("Unable to create enclave certificate verifier");

    log::info!("Created enclave certificate verifier");

    verifier
}

fn get_tdbe_config() -> TdbeConfig {
    log::info!("Fetching initial TDBE configuration");

    let config_stream =
        TcpStream::connect("init").expect("Unable to connect to initial configuration stream");
    let tdbe_config =
        TdbeConfig::read_from(config_stream).expect("Unable to read initial configuration");

    log::info!("Finished fetching initial TDBE configuration");

    tdbe_config
}

fn create_ra_context() -> Arc<EnclaveRaContext> {
    log::info!("Creating enclave remote attestation context");

    let certificate_expiration_time = {
        option_env!("CERTIFICATE_EXPIRATION_SECS").map(|s| {
            let sec = s
                .parse()
                .expect("invalid CERTIFICATE_EXPIRATION_SECS, expect u64");
            Duration::seconds(sec)
        })
    };
    let config = EnclaveRaConfig {
        sp_addr: "ra-sp-server".to_string(),
        certificate_validity_secs: DEFAULT_EXPIRATION_SECS as u32,
        certificate_expiration_time,
    };

    let enclave_ra_context =
        EnclaveRaContext::new(&config).expect("Unable to create new remote attestation context");

    log::info!("Created enclave remote attestation context");

    Arc::new(enclave_ra_context)
}

fn fetch_initial_data(
    context: &EnclaveRaContext,
    verifier: EnclaveCertVerifier,
    tdbe_dns_name: &str,
    transaction_ids: &[TxId],
) -> std::io::Result<()> {
    log::info!("Fetching initial data from another TDBE server");

    // Create attested TLS stream
    let mut tls_stream = create_tls_client_stream(context, verifier, tdbe_dns_name, "tdbe")?;

    // Create request to send to TDBE server
    let request = TrustedTdbeRequest::GetTransactionsWithOutputs {
        transaction_ids: transaction_ids.into(),
    };

    // Write request to stream
    request.write_to(&mut tls_stream)?;

    // Read response from stream
    let response = TrustedTdbeResponse::read_from(&mut tls_stream)?;

    match response {
        TrustedTdbeResponse::GetTransactionsWithOutputs { transactions } => {
            log::info!("{} transactions received", transactions.len())
        }
        TrustedTdbeResponse::Error { message } => {
            log::error!("Received error: {}", message);
            panic!("Cannot fetch initial data from another TDBE server");
        }
    }
    // TODO: Persist response

    log::info!("Finished fetching initial data from another TDBE server");

    Ok(())
}

fn create_tls_client_stream(
    context: &EnclaveRaContext,
    verifier: EnclaveCertVerifier,
    dns_name: &str,
    address: &str,
) -> std::io::Result<StreamOwned<ClientSession, TcpStream>> {
    log::info!("Creating enclave-to-enclave attested TLS client stream");
    let certificate = context
        .get_certificate()
        .expect("Unable to generate remote attestation certificate");

    let mut client_config = verifier.into_client_config();
    certificate
        .configure_client_config(&mut client_config)
        .expect("Unable to configure TLS client config with certificate");
    let client_config = Arc::new(client_config);

    let dns_name_ref = DNSNameRef::try_from_ascii_str(dns_name).expect("Invalid DNS name");

    let client_session = ClientSession::new(&client_config, dns_name_ref);
    let tcp_stream = match TcpStream::connect(address) {
        Ok(tcp_stream) => tcp_stream,
        Err(err) => {
            log::error!("Error while connecting to TCP stream");
            return Err(err);
        }
    };

    log::info!("Created enclave-to-enclave TLS client stream");

    Ok(StreamOwned::new(client_session, tcp_stream))
}

fn create_tls_server_stream(
    context: &EnclaveRaContext,
    verifier: EnclaveCertVerifier,
    stream: TcpStream,
) -> std::io::Result<StreamOwned<ServerSession, TcpStream>> {
    log::info!("Creating enclave-to-enclave attested TLS server stream");
    let certificate = context
        .get_certificate()
        .expect("Unable to create remote attestation certificate");
    let mut tls_server_config = verifier.into_client_verifying_server_config();

    certificate
        .configure_server_config(&mut tls_server_config)
        .expect("Unable to create TLS server config");

    let tls_server_config = Arc::new(tls_server_config);

    let tls_session = ServerSession::new(&tls_server_config);

    log::info!("Created enclave-to-enclave attested TLS server stream");

    Ok(StreamOwned::new(tls_session, stream))
}
