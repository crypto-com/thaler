mod handler;

pub use rs_libc::alloc::*;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
};

use chrono::Duration;
use parity_scale_codec::Encode;
use rustls::{ClientSession, ServerSession, StreamOwned};
use sgx_isa::Report;
use thread_pool::ThreadPool;
use webpki::DNSNameRef;

use chain_core::init::config::LightGenesis;
use chain_core::tx::data::TxId;
use enclave_macro::mock_key;
use enclave_protocol::{
    codec::{StreamRead, StreamWrite},
    tdbe_protocol::{PersistenceCommand, TrustedTdbeRequest, TrustedTdbeResponse},
};
use enclave_utils::tls::{create_ra_context, create_tls_client_stream, create_tls_server_stream};
use enclave_utils::SealedData;
use ra_client::{EnclaveCertVerifier, EnclaveCertVerifierConfig, EnclaveInfo};
use ra_enclave::{EnclaveRaConfig, EnclaveRaContext, DEFAULT_EXPIRATION_SECS};
use tdbe_common::TdbeStartupConfig;

const THREAD_POOL_SIZE: usize = 4;
const LIGHT_GENESIS: &str = include_str!("light_genesis.json");

/// returns the compiled in light client genesis trust basis
pub fn get_light_genesis() -> LightGenesis {
    serde_json::from_str(LIGHT_GENESIS).unwrap()
}

pub fn entry() -> std::io::Result<()> {
    // Initialize logger
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    // FIXME: init state / fetch old tx, ...
    // Get initial options provided in command line arguments
    let tdbe_config = get_tdbe_config();
    // the "temp_mock_feature" should be some separate thread with MLS state
    // + previous state to be exposed in the config + some option for genesis?
    if !tdbe_config.temp_mock_feature {
        // Get enclave certificate verifier
        let verifier = get_enclave_verifier();

        // Create remote attestation context
        let context = create_ra_context();

        // Fetch initial transaction data if TDBE is configured to connect to another TDBE server
        if let Some(ref remote_rpc_address) = tdbe_config.remote_rpc_address {
            let (tdbe_address, tdbe_dns_name) =
                fetch_remote_tdbe_connection_details(remote_rpc_address)?;
            let (transaction_ids, last_fetched_block) = fetch_transaction_ids();

            if let Err(err) = fetch_initial_data(
                &context,
                verifier.clone(),
                &tdbe_address,
                &tdbe_dns_name,
                &transaction_ids,
                last_fetched_block,
            ) {
                log::error!("Unable to fetch initial data from another TDBE server");
                return Err(err);
            }
        }

        // Connect to chain-abci
        log::info!("Connecting to chain-abci");
        let chain_abci = Arc::new(Mutex::new(TcpStream::connect("chain-abci")?));

        // Start TDBE server
        log::info!("Starting TBDE Server");
        let listener = TcpListener::bind("tdbe")?;

        // Create a thread pool for handling incoming connections
        let (thread_pool_sender, thread_pool) = ThreadPool::fixed_size(THREAD_POOL_SIZE);

        for stream in listener.incoming() {
            let context = context.clone();
            let verifier = verifier.clone();
            let chain_abci = chain_abci.clone();

            thread_pool_sender
                .send(move || {
                    // Create TLS stream
                    let tls_stream = create_tls_server_stream(
                        &context,
                        verifier,
                        stream.expect("Error while conntecting to incoming stream"),
                        true,
                    )
                    .expect("Unable to create TLS server stream");

                    // Handle client conntection
                    handle_connection(tls_stream, chain_abci);
                })
                .expect("Unable to send tasks to thread pool");
        }

        // Shut down thread pool when the listener is closed
        thread_pool.shutdown();
    } else {
        // Connect to tx-validation
        log::info!("Connecting to tx-validation");
        let tve_verifier = get_tve_enclave_verifier();
        let context = create_ra_context();
        let tve_uds = TcpStream::connect("tx-validation")?;
        let mut tve_stream = create_tls_server_stream(&context, tve_verifier, tve_uds, false)?;

        /// FIXME: this should be generated using "MLS-Exporter": https://github.com/crypto-com/thaler-docs/blob/master/docs/modules/tdbe.md#new-obfuscation-key
        const MOCK_KEY: [u8; 16] = mock_key!();
        tve_stream.write_all(&MOCK_KEY);
    }

    Ok(())
}

fn handle_connection<T: Read + Write>(mut stream: T, chain_abci: Arc<Mutex<TcpStream>>) {
    loop {
        match TrustedTdbeRequest::read_from(&mut stream) {
            Ok(tdbe_request) => {
                let tdbe_response = match tdbe_request {
                    TrustedTdbeRequest::GetTransactionsWithOutputs { transaction_ids } => {
                        match handler::get_transactions_with_outputs(
                            transaction_ids.into_owned(),
                            &mut chain_abci.lock().unwrap(),
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

fn get_tve_enclave_verifier() -> EnclaveCertVerifier {
    log::info!("Creating enclave certificate verifier for transaction validation");

    let enclave_info = EnclaveInfo::from_report_other_enclave(Report::for_self(), None);
    let verifier_config = EnclaveCertVerifierConfig::new_with_enclave_info(enclave_info);
    let verifier = EnclaveCertVerifier::new(verifier_config)
        .expect("Unable to create enclave certificate verifier");

    log::info!("Created enclave certificate verifier for transaction validation");

    verifier
}

fn get_tdbe_config() -> TdbeStartupConfig {
    log::info!("Fetching initial TDBE configuration");

    let config_stream =
        TcpStream::connect("init").expect("Unable to connect to initial configuration stream");
    let tdbe_config =
        TdbeStartupConfig::read_from(config_stream).expect("Unable to read initial configuration");

    log::info!("Finished fetching initial TDBE configuration");

    tdbe_config
}

/// Fetches connection details of remote TDBE server using TM RPC
fn fetch_remote_tdbe_connection_details(
    _remote_rpc_address: &str,
) -> std::io::Result<(String, String)> {
    // TODO: Fetch connection details using TM RPC (use `client-common::TendermintRpcClient`?)
    Ok(("".to_string(), "".to_string()))
}

// TODO: Get transaction IDs as mentioned in https://github.com/crypto-com/thaler-docs/blob/master/docs/modules/tdbe.md#light-client
fn fetch_transaction_ids() -> (Vec<TxId>, u32) {
    Default::default()
}

fn fetch_initial_data(
    context: &EnclaveRaContext,
    verifier: EnclaveCertVerifier,
    tdbe_address: &str,
    tdbe_dns_name: &str,
    transaction_ids: &[TxId],
    last_fetched_block: u32,
) -> std::io::Result<()> {
    log::info!("Fetching initial data from another TDBE server");

    // Create attested TLS stream
    let mut tls_stream = create_tls_client_stream(context, verifier, tdbe_dns_name, tdbe_address)?;

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
            // Connect to persistence stream
            log::info!("Connecting to persistence stream");
            let mut persistence = TcpStream::connect("persistence")?;

            for transaction in transactions {
                let transaction_id = transaction.id();
                let sealed_log: Vec<u8> = SealedData::seal(&transaction.encode(), transaction_id)
                    .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Unable to seal transaction")
                })?;

                let persistence_command = PersistenceCommand::Store {
                    transaction_id,
                    sealed_log,
                };

                persistence_command.write_to(&mut persistence)?;
            }

            let persistence_command = PersistenceCommand::Finish { last_fetched_block };
            persistence_command.write_to(&mut persistence)?;
        }
        TrustedTdbeResponse::Error { message } => {
            log::error!("Received error: {}", message);
            panic!("Cannot fetch initial data from another TDBE server");
        }
    }

    log::info!("Finished fetching initial data from another TDBE server");

    Ok(())
}
