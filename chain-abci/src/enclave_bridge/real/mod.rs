mod enclave_u;
mod server;
#[cfg(feature = "sgx-test")]
pub mod test;

use crate::enclave_bridge::real::enclave_u::{check_initchain, check_tx, end_block};
use crate::enclave_bridge::EnclaveProxy;
use chain_storage::ReadOnlyStorage;
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse};
use enclave_u_common::enclave_u::init_enclave;
use log::info;
use server::TxValidationServer;
use sgx_urts::SgxEnclave;
use std::sync::mpsc::channel;
use std::thread;

pub const TX_VALIDATION_ENCLAVE_FILE: &str = "tx_validation_enclave.signed.so";

pub struct TxValidationApp {
    enclave: SgxEnclave,
}

impl Default for TxValidationApp {
    fn default() -> Self {
        info!("Attempting to launch TX Validation Enclave in debug mode");
        let enclave = match init_enclave(TX_VALIDATION_ENCLAVE_FILE, true) {
            Ok(r) => {
                info!(
                    "[+] Init TX Validation Server Enclave Successful {}!",
                    r.geteid()
                );
                r
            }
            Err(x) => {
                panic!(
                    "[-] Init  TX Validation  Sercer Enclave Failed {}!",
                    x.as_str()
                );
            }
        };
        Self { enclave }
    }
}

impl EnclaveProxy for TxValidationApp {
    fn check_chain(&self, network_id: u8) -> Result<(), ()> {
        check_initchain(self.enclave.geteid(), network_id)
    }

    fn process_request(&mut self, request: IntraEnclaveRequest) -> IntraEnclaveResponse {
        let eid = self.enclave.geteid();
        match &request {
            IntraEnclaveRequest::EndBlock => end_block(eid, request),
            IntraEnclaveRequest::Encrypt(_) => {
                unreachable!("should be used only in TxValidationServer")
            }
            IntraEnclaveRequest::ValidateTx { .. } => check_tx(eid, request),
        }
    }
}

/// It launches a ZMQ server that can server tx-query requests;
/// (used to be in a separate process -- tx-validation-app that had a custom storage;
/// now it's in a thread of chain-abci and shares its storage)
pub fn start_zmq(
    zmq_conn_str: &str,
    network_id: u8,
    storage: ReadOnlyStorage,
) -> thread::JoinHandle<()> {
    info!("Attempting to launch TX Validation Enclave (for tx-query / zmq) in debug mode");
    let enclave = match init_enclave(TX_VALIDATION_ENCLAVE_FILE, true) {
        Ok(r) => {
            info!(
                "[+] Init TX Validation Server Enclave (for tx-query / zmq) Successful {}!",
                r.geteid()
            );
            r
        }
        Err(x) => {
            panic!(
                "[-] Init  TX Validation Server Enclave (for tx-query / zmq) Failed {}!",
                x.as_str()
            );
        }
    };
    let (sender, receiver) = channel();
    let mut server: TxValidationServer =
        TxValidationServer::new(zmq_conn_str, enclave, storage, network_id, sender)
            .expect("could not start a zmq server");
    info!("starting zmq server");
    let child_t = thread::spawn(move || server.execute());
    receiver.recv().unwrap();
    child_t
}
