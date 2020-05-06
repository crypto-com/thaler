mod zmq_helper;

use std::env;
use std::io::Result;
use std::pin::Pin;

use aesm_client::AesmClient;
use enclave_runner::usercalls::{AsyncStream, UsercallExtension};
use enclave_runner::EnclaveBuilder;
use futures::future::{Future, FutureExt};
use log::info;
use sgxs_loaders::isgx::Device as IsgxDevice;

use self::zmq_helper::ZmqHelper;

#[derive(Debug)]
struct ZmqService {
    pub connection_str: String,
}

impl UsercallExtension for ZmqService {
    fn connect_stream<'a>(
        &'a self,
        addr: &'a str,
        _local_addr: Option<&'a mut String>,
        _peer_addr: Option<&'a mut String>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Box<dyn AsyncStream>>>> + 'a>> {
        async move {
            match &*addr {
                "zmq" => {
                    info!("enclave helper: connecting to zmq");
                    let stream = ZmqHelper::new(&self.connection_str);
                    let boxed_stream: Box<dyn AsyncStream> = Box::new(stream);
                    let option: Option<Box<dyn AsyncStream>> = Some(boxed_stream);
                    Ok(option)
                }
                _ => Ok(None),
            }
        }
        .boxed_local()
    }
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Please provide: <ENCLAVE_PATH> <ZMQ_CONN_STR>
        ENCLAVE_PATH: the path to *.sgxs file (note signature file be with it)
        ZMQ_CONN_STR: the ZMQ connection string (e.g. \"ipc://enclave.ipc\" or \"tcp://127.0.0.1:25933\") of the tx-validation server (now in chain-abci)
        ");
        std::process::exit(1);
    }
    let mut device = IsgxDevice::new()
        .expect("sgx device was not found")
        .einittoken_provider(AesmClient::new())
        .build();
    let mut enclave_builder = EnclaveBuilder::new(args[1].as_ref());
    // can use `enclave_builder.dummy_signature()` in testing
    enclave_builder
        .coresident_signature()
        .expect("enclave signature file not found");
    enclave_builder.usercall_extension(ZmqService {
        connection_str: args[2].clone(),
    });
    let enclave = enclave_builder
        .build(&mut device)
        .expect("failed to build an enclave");
    enclave.run().expect("failed to start an enclave");
}
