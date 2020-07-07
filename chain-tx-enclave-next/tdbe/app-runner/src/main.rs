use std::{future::Future, io, pin::Pin};

use aesm_client::AesmClient;
use enclave_runner::{
    usercalls::{AsyncListener, AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use sgxs_loaders::isgx::Device;
use structopt::StructOpt;
use tokio::net::{TcpListener, TcpStream};

use enclave_utils::zmq_helper::ZmqHelper;

#[derive(Debug, StructOpt)]
#[structopt(name = "tx-query-runner", about = "tx-query enclave runner")]
struct Options {
    /// Path to enclave file (`.sgxs`). Note that `.sig` file is also expected to be at same
    /// location
    #[structopt(short, long)]
    pub enclave_path: String,
    /// ZeroMQ connection string of tx-validation server (now in chain-abci). E.g.
    /// `ipc://enclave.ipc` or `tcp://127.0.0.1:25933`
    #[structopt(short, long)]
    pub zmq_conn_str: String,
    /// `ra-sp-server` address for remote attestation. E.g. `0.0.0.0:8989`
    #[structopt(short, long)]
    pub sp_address: String,
    /// Optional address of another TDBE server from where to fetch data
    ///
    /// FIXME: This is a temporary solution for letting the TDBE know when it has to connect to
    /// other TDBE server. Ideally this configuration can be pushed to TDBE using some "config
    /// stream"
    #[structopt(short, long)]
    pub tdbe_address: Option<String>,
    /// TDBE server address. E.g. `127.0.0.1:3445`
    #[structopt(short, long)]
    pub address: String,
    /// Use dummy signature in testing
    #[structopt(short, long)]
    pub test: bool,
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
