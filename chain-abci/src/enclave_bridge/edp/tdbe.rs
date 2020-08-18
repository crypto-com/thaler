use std::{
    future::Future,
    io::{self, Cursor, Seek, SeekFrom},
    os::unix::net::UnixStream,
    pin::Pin,
    thread,
};

use aesm_client::AesmClient;
use enclave_runner::{
    usercalls::{AsyncListener, AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use sgxs_loaders::isgx::Device;
use tdbe_common::TdbeStartupConfig;
use tokio::net::{TcpListener, TcpStream};

use chain_core::tx::data::TxId;
use enclave_protocol::codec::StreamWrite;

#[derive(Debug)]
pub struct TdbeApp {
    /// Path to enclave file (`.sgxs`). Note that `.sig` file is also expected to be at same
    /// location
    ///
    /// TODO: Assume enclave file to be in current path?
    pub enclave_path: String,
    /// `ra-sp-server` address for remote attestation. E.g. `0.0.0.0:8989`
    ///
    /// TODO:  Replace it with a local UDS (using `chain-abci` as launcher).
    pub sp_address: String,
    /// Optional address of another TDBE server from where to fetch data
    pub remote_tdbe_address: Option<String>,
    /// Optional DNS name of another TDBE server from where to fetch data
    ///
    /// TODO: Obtain this using RPC
    pub remote_tdbe_dns_name: Option<String>,
    /// Local TDBE server address to listen on. E.g. `127.0.0.1:3445`
    pub local_listen_address: String,
    /// External TDBE server address, used by remote nodes to send RPC requests. E.g.
    /// `<public_ip>:<public_port>`
    pub external_listen_address: String,
    /// UDS to connect to `chain-abci`
    pub chain_abci_stream: UnixStream,
    /// UDS to connect to `tx-validation`
    pub tx_validation_stream: UnixStream,
    /// Transaction IDs for testing
    ///
    /// TODO: Obtain transaction IDs using https://github.com/crypto-com/chain-docs/blob/master/docs/modules/tdbe.md#how-to-obtain-the-list-of-all-the-transactions-using-tendermint-light-client
    pub txids: Vec<String>,
    /// Use dummy signature in testing
    pub test: bool,
}

impl TdbeApp {
    fn validate(&self) {
        match (
            self.remote_tdbe_address.as_ref(),
            self.remote_tdbe_dns_name.as_ref(),
        ) {
            (Some(_), None) | (None, Some(_)) => {
                panic!("Either both, `remote-tdbe-address` and `remote-tdbe-dns-name` should be provided or none of them should be provided");
            }
            _ => {
                // Options are valid
            }
        }
    }
}

#[allow(clippy::type_complexity)]
impl UsercallExtension for TdbeApp {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Option<Box<dyn AsyncStream>>>> + 'future>> {
        async fn connect_stream_inner(
            this: &TdbeApp,
            addr: &str,
        ) -> io::Result<Option<Box<dyn AsyncStream>>> {
            match addr {
                "init" => {
                    let transaction_ids = parse_transaction_ids(&this.txids);

                    let tdbe_startup_config = TdbeStartupConfig {
                        transaction_ids,
                        tdbe_dns_name: this.remote_tdbe_dns_name.clone(),
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
                "tx-validation" => {
                    let stream =
                        tokio::net::UnixStream::from_std(this.tx_validation_stream.try_clone()?)?;
                    Ok(Some(Box::new(stream)))
                }
                "chain-abci" => {
                    let stream =
                        tokio::net::UnixStream::from_std(this.chain_abci_stream.try_clone()?)?;
                    Ok(Some(Box::new(stream)))
                }
                "ra-sp-server" => {
                    let stream = TcpStream::connect(&this.sp_address).await?;
                    Ok(Some(Box::new(stream)))
                }
                "tdbe" => match this.remote_tdbe_address {
                    Some(ref tdbe_address) => {
                        let stream = TcpStream::connect(tdbe_address).await?;
                        Ok(Some(Box::new(stream)))
                    }
                    None => {
                        log::error!("Attempting to connect to remote TDBE server but no address provided at startup.");
                        Ok(None)
                    }
                },
                _ => Ok(None),
            }
        }

        Box::pin(connect_stream_inner(self, addr))
    }

    fn bind_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Option<Box<dyn AsyncListener>>>> + 'future>> {
        async fn bind_stream_inner(
            this: &TdbeApp,
            addr: &str,
        ) -> io::Result<Option<Box<dyn AsyncListener>>> {
            match addr {
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

pub fn spawn_tdbe(tdbe_app: TdbeApp) {
    tdbe_app.validate();

    thread::spawn(move || {
        let mut device = Device::new()
            .expect("SGX device was not found")
            .einittoken_provider(AesmClient::new())
            .build();
        let enclave_path = tdbe_app.enclave_path.clone();
        let mut enclave_builder = EnclaveBuilder::new(enclave_path.as_ref());

        enclave_builder
            .coresident_signature()
            .expect("Enclave signature file not found");
        enclave_builder.usercall_extension(tdbe_app);

        let enclave = enclave_builder
            .build(&mut device)
            .expect("Failed to build enclave");
        enclave.run().expect("Failed to start enclave")
    });
}

fn parse_transaction_ids(txids: &[String]) -> Vec<TxId> {
    txids
        .iter()
        .map(|txid_str| {
            let mut txid = TxId::default();
            hex::decode_to_slice(txid_str, &mut txid).expect("Invalid transaction ID passed");
            txid
        })
        .collect()
}
