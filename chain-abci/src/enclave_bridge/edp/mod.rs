mod server;
pub mod tdbe;

use crate::enclave_bridge::EnclaveProxy;
use aesm_client::AesmClient;
use chain_core::tx::TX_AUX_SIZE;
use chain_storage::ReadOnlyStorage;
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse};
use enclave_runner::{
    usercalls::{AsyncListener, AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use parity_scale_codec::{Decode, Encode};
use sgxs_loaders::isgx::Device;
use std::io::{Read, Write};
use std::sync::{mpsc::channel, Arc, Mutex};
use std::thread;
use std::{future::Future, io, pin::Pin};

use ra_sp_server::{config::SpRaConfig, server::SpRaServer};
use tokio::net::{TcpListener, TcpStream};

use std::os::unix::net::UnixStream;

const REMOTE_ATTESTATION_PROXY: &str = "ra-sp-server";

/// pair of unix domain sockets
/// enclave_stream / tdbe_stream is only needed / passed in `connect_stream`
/// `runner_stream` is shared in chain-abci app
/// TODO: separate out the "chain-abci-side" runner_stream and "usercall extensions"-side
/// (enclave_stream / tdbe_stream)
#[derive(Debug)]
pub struct TxValidationApp {
    enclave_stream: Option<UnixStream>,
    runner_stream: Arc<Mutex<UnixStream>>,
    /// `ra-sp-server` address for remote attestation. E.g. `0.0.0.0:8989`
    /// FIXME: enclave direct connection -- not via TCP proxy
    sp_address: Option<String>,
    tdbe_stream: Option<UnixStream>,
}

impl TxValidationApp {
    /// only used for `TxValidationServer`/`chain-abci` having access to "runner_stream",
    /// _not for enclave launching_
    pub fn get_comm_only(&self) -> Self {
        Self {
            enclave_stream: None,
            runner_stream: self.runner_stream.clone(),
            sp_address: None,
            tdbe_stream: None,
        }
    }

    fn new(sp_address: String) -> (Self, UnixStream) {
        let (sender, receiver) = UnixStream::pair().expect("init chain-abci<->tve socket");
        let (from_tdbe_to_tve, from_tve_to_tdbe) =
            UnixStream::pair().expect("init tve<->tdbe socket");

        (
            Self {
                enclave_stream: Some(receiver),
                runner_stream: Arc::new(Mutex::new(sender)),
                sp_address: Some(sp_address),
                tdbe_stream: Some(from_tve_to_tdbe),
            },
            from_tdbe_to_tve,
        )
    }
}

/// type aliases for outputs in UsercallExtension async return types
pub type UserCallStream = io::Result<Option<Box<dyn AsyncStream>>>;
pub type UserCallListener = io::Result<Option<Box<dyn AsyncListener>>>;

impl UsercallExtension for TxValidationApp {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = UserCallStream> + 'future>> {
        async fn connect_stream_inner(this: &TxValidationApp, addr: &str) -> UserCallStream {
            match addr {
                "chain-abci" => {
                    if let Some(enclave_stream) = this.enclave_stream.as_ref() {
                        let stream = tokio::net::UnixStream::from_std(enclave_stream.try_clone()?)?;
                        Ok(Some(Box::new(stream)))
                    } else {
                        Ok(None)
                    }
                }
                REMOTE_ATTESTATION_PROXY => {
                    if let Some(ra_address) = this.sp_address.as_ref() {
                        let stream = TcpStream::connect(ra_address).await?;
                        Ok(Some(Box::new(stream)))
                    } else {
                        Ok(None)
                    }
                }
                "tdbe" => {
                    if let Some(enclave_stream) = this.tdbe_stream.as_ref() {
                        let stream = tokio::net::UnixStream::from_std(enclave_stream.try_clone()?)?;
                        Ok(Some(Box::new(stream)))
                    } else {
                        Ok(None)
                    }
                }
                _ => Ok(None),
            }
        }

        Box::pin(connect_stream_inner(self, addr))
    }
}

impl EnclaveProxy for TxValidationApp {
    fn check_chain(&mut self, network_id: u8) -> Result<(), ()> {
        self.process_request(IntraEnclaveRequest::InitChainCheck(network_id))
            .map(|_| ())
            .map_err(|_| ())
    }

    fn process_request(&mut self, request: IntraEnclaveRequest) -> IntraEnclaveResponse {
        let mut stream = self
            .runner_stream
            .lock()
            .expect("lock for tx-validation request-reply");
        stream
            .write_all(&request.encode())
            .expect("write enclave request");
        let mut request_buf = vec![0u8; 2 * TX_AUX_SIZE];
        match stream.read(&mut request_buf) {
            Ok(c) => match IntraEnclaveResponse::decode(&mut request_buf[..c].as_ref()) {
                Ok(response) => response,
                Err(e) => {
                    log::error!("enclave response decode error {:?}", e);
                    Err(chain_tx_validation::Error::EnclaveRejected)
                }
            },
            Err(e) => {
                log::error!("enclave response decode error {:?}", e);
                Err(chain_tx_validation::Error::EnclaveRejected)
            }
        }
    }
}

/// Launches tx-validation enclave --
/// it expects "tx-validation-next.sgxs" (+ signature)
/// to be in the same directory as chain-abci
/// it returns the "copied" app (for `TxValidationServer` / chain-abci)
/// + the unix stream for transaction data bootstrapping enclave
pub fn launch_tx_validation(ra_proxy_address: String) -> (TxValidationApp, UnixStream) {
    let (app, from_tdbe_to_tve) = TxValidationApp::new(ra_proxy_address);
    let app2 = app.get_comm_only();
    let mut device = Device::new()
        .expect("SGX device was not found")
        .einittoken_provider(AesmClient::new())
        .build();
    let enclave_path = "tx-validation-next.sgxs";
    let mut enclave_builder = EnclaveBuilder::new(enclave_path.as_ref());
    enclave_builder
        .coresident_signature()
        .expect("Enclave signature file not found");

    enclave_builder.usercall_extension(app);
    let enclave = enclave_builder
        .build(&mut device)
        .expect("Failed to build enclave");
    thread::spawn(|| {
        log::info!("starting tx validation enclave");
        enclave.run().expect("Failed to start enclave")
    });
    (app2, from_tdbe_to_tve)
}

/// Temporary tx query launching options
#[derive(Debug)]
pub struct TempTxQueryOptions {
    /// FIXME: split up encryption to direct attested TLS to tx-validation (over unix domain socket
    /// provided both to tx-validation and tx-query enclaves)
    pub chain_abci_data: UnixStream,
    /// `ra-sp-server` address for remote attestation. E.g. `0.0.0.0:8989`
    /// FIXME: enclave direct connection -- not via TCP proxy
    pub sp_address: String,
    /// tx-query server address. E.g. `127.0.0.1:3443`
    pub address: String,
}

impl UsercallExtension for TempTxQueryOptions {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = UserCallStream> + 'future>> {
        async fn connect_stream_inner(
            this: &TempTxQueryOptions,
            addr: &str,
        ) -> io::Result<Option<Box<dyn AsyncStream>>> {
            match addr {
                "chain-abci-data" => {
                    let stream =
                        tokio::net::UnixStream::from_std(this.chain_abci_data.try_clone()?)?;
                    Ok(Some(Box::new(stream)))
                }
                REMOTE_ATTESTATION_PROXY => {
                    let stream = TcpStream::connect(&this.sp_address).await?;
                    Ok(Some(Box::new(stream)))
                }
                _ => Ok(None),
            }
        }

        Box::pin(connect_stream_inner(self, addr))
    }

    fn bind_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = UserCallListener> + 'future>> {
        async fn bind_stream_inner(this: &TempTxQueryOptions, addr: &str) -> UserCallListener {
            match addr {
                "tx-query" => {
                    let listener = TcpListener::bind(&this.address).await?;
                    Ok(Some(Box::new(listener)))
                }
                _ => Ok(None),
            }
        }

        Box::pin(bind_stream_inner(self, addr))
    }
}

/// starts up remote attestation proxy and tx-query enclave
pub fn temp_start_up_ra_tx_query<T: EnclaveProxy + 'static>(
    ra_config: Option<SpRaConfig>,
    tx_query_options: TempTxQueryOptions,
    proxy: T,
    network_id: u8,
    storage: ReadOnlyStorage,
    socket_to_enclave: UnixStream,
) {
    if let Some(ra_config) = ra_config {
        let ra_address = ra_config.address.clone();
        let _ = thread::spawn(|| {
            log::info!("starting remote attestation proxy");
            let server = SpRaServer::new(ra_config).unwrap();
            server.run(ra_address).unwrap();
        });
    }
    let _ = thread::spawn(|| {
        log::info!("starting tx-query");
        let mut device = Device::new()
            .expect("SGX device was not found")
            .einittoken_provider(AesmClient::new())
            .build();
        let mut enclave_builder = EnclaveBuilder::new("tx-query2-enclave-app.sgxs".as_ref());
        enclave_builder
            .coresident_signature()
            .expect("Enclave signature file not found");

        enclave_builder.usercall_extension(tx_query_options);

        let enclave = enclave_builder
            .build(&mut device)
            .expect("Failed to build enclave");
        enclave.run().expect("Failed to start enclave")
    });

    let (sender, receiver) = channel();
    let mut server =
        server::TxValidationServer::new(socket_to_enclave, proxy, storage, network_id, sender);
    log::info!("starting tx-query data handling server");
    let _child_t = thread::spawn(move || server.execute());
    receiver.recv().unwrap();
}
