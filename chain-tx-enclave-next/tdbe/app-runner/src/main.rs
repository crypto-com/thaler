use std::{
    future::Future,
    io::{self, Cursor, Seek, SeekFrom},
    pin::Pin,
};

use aesm_client::AesmClient;
use enclave_runner::{
    usercalls::{AsyncListener, AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use sgxs_loaders::isgx::Device;
use structopt::StructOpt;
use tokio::net::{TcpListener, TcpStream};

use chain_core::tx::data::TxId;
use enclave_protocol::codec::StreamWrite;
use enclave_utils::zmq_helper::ZmqHelper;
use tdbe_common::TdbeConfig;

#[derive(Debug, StructOpt)]
#[structopt(name = "tx-query-runner", about = "tx-query enclave runner")]
struct Options {
    /// Path to enclave file (`.sgxs`). Note that `.sig` file is also expected to be at same
    /// location
    #[structopt(short = "e", long = "enclave-path")]
    pub enclave_path: String,
    /// ZeroMQ connection string of tx-validation server (now in chain-abci). E.g.
    /// `ipc://enclave.ipc` or `tcp://127.0.0.1:25933`
    #[structopt(short = "zmq", long = "zmq-conn-str")]
    pub zmq_conn_str: String,
    /// `ra-sp-server` address for remote attestation. E.g. `0.0.0.0:8989`
    #[structopt(long = "sp-address")]
    pub sp_address: String,
    /// Optional address of another TDBE server from where to fetch data
    #[structopt(long = "tdbe-address")]
    pub tdbe_address: Option<String>,
    /// Optional DNS name of another TDBE server from where to fetch data
    #[structopt(long = "tdbe-dns-name")]
    pub tdbe_dns_name: Option<String>,
    /// TDBE server address. E.g. `127.0.0.1:3445`
    #[structopt(short = "a", long = "address")]
    pub address: String,
    /// Transaction IDs for testing
    #[structopt(long = "txids")]
    pub txids: Vec<String>,
    /// Use dummy signature in testing
    #[structopt(short = "t", long = "test")]
    pub test: bool,
}

impl Options {
    /// Validates provided command line options
    fn validate(&self) {
        match (self.tdbe_address.as_ref(), self.tdbe_dns_name.as_ref()) {
            (Some(_), None) | (None, Some(_)) => {
                panic!("Either both, `tdbe-address` and `tdbe-dns-name` should be provided or none of them should be provided");
            }
            _ => {
                // Options are valid
            }
        }
    }
}

#[allow(clippy::type_complexity)]
impl UsercallExtension for Options {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Option<Box<dyn AsyncStream>>>> + 'future>> {
        async fn connect_stream_inner(
            this: &Options,
            addr: &str,
        ) -> io::Result<Option<Box<dyn AsyncStream>>> {
            match addr {
                "init" => {
                    let transaction_ids = parse_transaction_ids(&this.txids);

                    let tdbe_config = TdbeConfig {
                        transaction_ids,
                        tdbe_dns_name: this.tdbe_dns_name.clone(),
                    };

                    let mut stream = Cursor::new(Vec::new());
                    tdbe_config
                        .write_to(&mut stream)
                        .expect("Unable to write initial configuration to `Cursor`");

                    stream
                        .seek(SeekFrom::Start(0))
                        .expect("Unable to seek to starting position on a Cursor");

                    Ok(Some(Box::new(stream)))
                }
                "zmq" => {
                    let zmq_helper = ZmqHelper::new(&this.zmq_conn_str)?;
                    Ok(Some(Box::new(zmq_helper)))
                }
                "ra-sp-server" => {
                    let stream = TcpStream::connect(&this.sp_address).await?;
                    Ok(Some(Box::new(stream)))
                }
                "tdbe" => match this.tdbe_address {
                    Some(ref tdbe_address) => {
                        let stream = TcpStream::connect(tdbe_address).await?;
                        Ok(Some(Box::new(stream)))
                    }
                    None => {
                        log::error!("Attempting to connect to another TDBE server but no address provided at startup.");
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
            this: &Options,
            addr: &str,
        ) -> io::Result<Option<Box<dyn AsyncListener>>> {
            match addr {
                "tdbe" => {
                    let listener = TcpListener::bind(&this.address).await?;
                    Ok(Some(Box::new(listener)))
                }
                _ => Ok(None),
            }
        }

        Box::pin(bind_stream_inner(self, addr))
    }
}

fn main() {
    env_logger::init();

    let options = Options::from_args();
    options.validate();

    let mut device = Device::new()
        .expect("SGX device was not found")
        .einittoken_provider(AesmClient::new())
        .build();
    let enclave_path = options.enclave_path.clone();
    let mut enclave_builder = EnclaveBuilder::new(enclave_path.as_ref());

    if options.test {
        log::warn!("Running in test mode using dummy_signature");
        enclave_builder.dummy_signature();
    } else {
        enclave_builder
            .coresident_signature()
            .expect("Enclave signature file not found");
    }

    enclave_builder.usercall_extension(options);

    let enclave = enclave_builder
        .build(&mut device)
        .expect("Failed to build enclave");
    enclave.run().expect("Failed to start enclave")
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
