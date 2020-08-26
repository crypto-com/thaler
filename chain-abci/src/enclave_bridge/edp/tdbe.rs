use std::{
    collections::HashMap,
    future::Future,
    io::{Cursor, Seek, SeekFrom},
    os::unix::net::UnixStream,
    pin::Pin,
    sync::Arc,
    thread,
    thread::JoinHandle,
};

use aesm_client::AesmClient;
use enclave_runner::{usercalls::UsercallExtension, EnclaveBuilder};
use kvdb::KeyValueDB;
use sgxs_loaders::isgx::Device;
use tdbe_common::TdbeStartupConfig;
use tokio::net::{TcpListener, TcpStream};

use chain_core::tx::data::TxId;
use chain_storage::ReadOnlyStorage;
use enclave_protocol::{
    codec::{StreamRead, StreamWrite},
    tdbe_protocol::PersistenceCommand,
    EnclaveRequest, EnclaveResponse, SealedLog,
};
use ra_sp_server::config::SpRaConfig;

use crate::enclave_bridge::{
    edp::{UserCallListener, UserCallStream},
    TdbeConfig,
};

#[derive(Debug)]
pub struct TdbeApp {
    /// UDS to connect to `chain-abci`
    chain_abci_stream: UnixStream,
    /// UDS to persist data to `chain-storage`
    persistence_stream: UnixStream,
    /// `ra-sp-server` address for remote attestation. E.g. `0.0.0.0:8989`
    /// TODO:  Replace it with a local UDS (using `chain-abci` as launcher).
    sp_address: String,
    /// Optional address of remote TDBE server for fetching initial data
    remote_rpc_address: Option<String>,
    /// Local TDBE server address to listen on. E.g. `127.0.0.1:3445`
    local_listen_address: String,
    /// UDS to push secrets to tx-validation enclave
    tve_stream: UnixStream,
}

impl TdbeApp {
    /// Creates a new instance of TDBE app
    pub fn new(
        tdbe_config: &TdbeConfig,
        ra_config: &SpRaConfig,
        _storage: Arc<dyn KeyValueDB>,
        tve_stream: UnixStream,
    ) -> std::io::Result<Self> {
        // - `chain_abci_stream` is passed to enclave. Encalve can send requests to chain-abci
        //   using this
        // - `chain_abci_receiver` listens to the requests sent by enclave and responds to them
        let (chain_abci_stream, _chain_abci_receiver) = UnixStream::pair()?;

        // - `persistence_stream` is passed to enclave. Encalve can send requests to chain-storage
        //   using this
        // - `persistence_receiver` listens to the requests sent by enclave and responds to them
        let (persistence_stream, _persistence_receiver) = UnixStream::pair()?;

        // FIXME: spawn these when they actually do something
        // spawn_chain_abci_thread(chain_abci_receiver, storage.clone());
        // spawn_persistence_thread(persistence_receiver, storage);

        Ok(Self {
            chain_abci_stream,
            persistence_stream,
            sp_address: ra_config.address.clone(),
            remote_rpc_address: tdbe_config.remote_rpc_address.clone(),
            local_listen_address: tdbe_config.local_listen_address.clone(),
            tve_stream,
        })
    }

    pub fn spawn(self) -> JoinHandle<()> {
        thread::spawn(move || {
            let mut device = Device::new()
                .expect("SGX device was not found")
                .einittoken_provider(AesmClient::new())
                .build();
            let mut enclave_builder = EnclaveBuilder::new("tdb-enclave-app.sgxs".as_ref());

            enclave_builder
                .coresident_signature()
                .expect("Enclave signature file not found");
            enclave_builder.usercall_extension(self);

            let enclave = enclave_builder
                .build(&mut device)
                .expect("Failed to build enclave");
            enclave.run().expect("Failed to start enclave")
        })
    }
}

#[allow(dead_code)]
fn spawn_chain_abci_thread(mut receiver: UnixStream, storage: Arc<dyn KeyValueDB>) {
    let _ = thread::spawn(move || {
        let storage = chain_storage::ReadOnlyStorage::new_db(storage);

        while let Ok(enclave_request) = EnclaveRequest::read_from(&mut receiver) {
            match enclave_request {
                EnclaveRequest::GetSealedTxData { txids } => {
                    let response =
                        EnclaveResponse::GetSealedTxData(get_sealed_tx_data(txids, &storage));
                    response
                        .write_to(&mut receiver)
                        .expect("Unable to write to TDBE <-> chain-abci unix stream");
                }
                _ => unreachable!("TDBE can only send `GetSealedTxData` request"),
            }
        }
    });
}

fn get_sealed_tx_data(txids: Vec<TxId>, storage: &ReadOnlyStorage) -> Option<Vec<SealedLog>> {
    let mut result = Vec::with_capacity(txids.len());

    for txid in txids {
        if let Some(txin) = storage.get_sealed_log(&txid) {
            result.push(txin);
        } else {
            return None;
        }
    }

    Some(result)
}

/// FIXME: should this start a background thread if this is one-off and the main thread needs to wait for its completion?
#[allow(dead_code)]
fn spawn_persistence_thread(mut receiver: UnixStream, storage: Arc<dyn KeyValueDB>) {
    let _ = thread::spawn(move || {
        let mut storage = chain_storage::Storage::new_db(storage);
        let mut buffer = HashMap::new();
        let mut kvdb = chain_storage::buffer::BufferStore::new(&storage, &mut buffer);

        while let Ok(persistence_command) = PersistenceCommand::read_from(&mut receiver) {
            match persistence_command {
                PersistenceCommand::Store {
                    transaction_id,
                    sealed_log,
                } => chain_storage::store_sealed_log(&mut kvdb, &transaction_id, &sealed_log),
                PersistenceCommand::Finish { last_fetched_block } => {
                    chain_storage::set_last_fetched_block(&mut kvdb, last_fetched_block);
                    break;
                }
                _ => {
                    // FIXME
                }
            }
        }

        chain_storage::buffer::flush_storage(&mut storage, std::mem::take(&mut buffer))
            .expect("Unable to flush storage");
    });
}

impl UsercallExtension for TdbeApp {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = UserCallStream> + 'future>> {
        async fn connect_stream_inner(this: &TdbeApp, addr: &str) -> UserCallStream {
            match addr {
                // Passes initial startup configuration to enclave
                "init" => {
                    let tdbe_startup_config = TdbeStartupConfig {
                        remote_rpc_address: this.remote_rpc_address.clone(),
                        temp_mock_feature: true,
                    };

                    let mut stream = Cursor::new(Vec::new());
                    tdbe_startup_config
                        .write_to(&mut stream)
                        .expect("Unable to write initial configuration to `Cursor`");

                    stream
                        .seek(SeekFrom::Start(0))
                        .expect("Unable to seek to starting position on a Cursor");

                    Ok(Some(Box::new(stream)))
                }
                // Connects enclave to chain-abci
                "chain-abci" => {
                    let stream =
                        tokio::net::UnixStream::from_std(this.chain_abci_stream.try_clone()?)?;
                    Ok(Some(Box::new(stream)))
                }
                // Connects enclave to ra-sp-server
                "ra-sp-server" => {
                    let stream = TcpStream::connect(&this.sp_address).await?;
                    Ok(Some(Box::new(stream)))
                }
                "tx-validation" => {
                    let stream = tokio::net::UnixStream::from_std(this.tve_stream.try_clone()?)?;
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
        async fn bind_stream_inner(this: &TdbeApp, addr: &str) -> UserCallListener {
            match addr {
                // Binds TCP listener for TDBE server
                "tdbe" => {
                    let listener = TcpListener::bind(&this.local_listen_address).await?;
                    Ok(Some(Box::new(listener)))
                }
                _ => Ok(None),
            }
        }

        Box::pin(bind_stream_inner(self, addr))
    }
}
