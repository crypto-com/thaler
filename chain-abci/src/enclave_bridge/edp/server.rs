use crate::app::ChainNodeState;
use crate::enclave_bridge::EnclaveProxy;
use chain_core::state::account::StakedState;
use chain_core::state::account::StakedStateOpWitness;
use chain_core::tx::data::TxId;
use chain_storage::buffer::Get;
use chain_storage::jellyfish::StakingGetter;
use chain_storage::ReadOnlyStorage;
use chain_tx_validation::witness::verify_tx_recover_address;
use chain_tx_validation::ChainInfo;
use enclave_protocol::codec::StreamWrite;
use enclave_protocol::IntraEnclaveRequest;
use enclave_protocol::{
    EnclaveRequest, EnclaveResponse, IntraEnclaveResponseOk, IntraEncryptRequest,
    ENCRYPTION_REQUEST_SIZE,
};
use parity_scale_codec::Decode;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::Sender;

pub struct TxValidationServer<T: EnclaveProxy> {
    socket_to_enclave: UnixStream,
    enclave: T,
    storage: ReadOnlyStorage,
    network_id: u8,
    start_signal: Sender<()>,
}

impl<T: EnclaveProxy> TxValidationServer<T> {
    pub fn new(
        socket_to_enclave: UnixStream,
        enclave: T,
        storage: ReadOnlyStorage,
        network_id: u8,
        start_signal: Sender<()>,
    ) -> Self {
        Self {
            socket_to_enclave,
            enclave,
            storage,
            network_id,
            start_signal,
        }
    }

    fn lookup_txids<I>(&self, inputs: I) -> Option<Vec<Vec<u8>>>
    where
        I: IntoIterator<Item = TxId> + ExactSizeIterator,
    {
        let mut result = Vec::with_capacity(inputs.len());
        for input in inputs.into_iter() {
            if let Some(txin) = self.storage.get_sealed_log(&input) {
                result.push(txin);
            } else {
                return None;
            }
        }
        Some(result)
    }

    fn lookup_state(
        &self,
        txid: &TxId,
        sig: &StakedStateOpWitness,
        last_version: u64,
    ) -> Option<StakedState> {
        let account_getter = StakingGetter::new(&self.storage, last_version);
        let address = verify_tx_recover_address(sig, txid).ok()?;
        account_getter.get(&address)
    }

    pub fn execute(&mut self) {
        log::info!("running zmq server");
        self.start_signal.send(()).unwrap();
        let mut request = vec![0u8; ENCRYPTION_REQUEST_SIZE];
        loop {
            if let Ok(r_len) = self.socket_to_enclave.read(&mut request) {
                log::debug!("received a message");
                let mcmd = EnclaveRequest::decode(&mut request[..r_len].as_ref());
                let resp = match mcmd {
                    Ok(EnclaveRequest::GetSealedTxData { txids }) => {
                        EnclaveResponse::GetSealedTxData(self.lookup_txids(txids.iter().copied()))
                    }
                    Ok(EnclaveRequest::EncryptTx(req)) => {
                        let result = {
                            let tx_inputs = match req.tx_inputs {
                                Some(inputs) => self.lookup_txids(inputs.iter().map(|x| x.id)),
                                _ => None,
                            };
                            match self.storage.get_last_app_state() {
                                Some(state) => {
                                    let last_state = ChainNodeState::decode(&mut state.as_slice())
                                        .expect("deserialize app state");
                                    let account = match req.op_sig {
                                        Some(sig) => self.lookup_state(
                                            &req.txid,
                                            &sig,
                                            last_state.staking_version,
                                        ),
                                        _ => None,
                                    };
                                    // TODO: fee in enclave?

                                    let min_fee = last_state
                                        .top_level
                                        .network_params
                                        .calculate_fee(req.tx_size as usize)
                                        .expect("valid fee");
                                    let info = ChainInfo {
                                        min_fee_computed: min_fee,
                                        chain_hex_id: self.network_id,
                                        block_time: last_state.block_time,
                                        block_height: last_state.block_height,
                                        max_evidence_age: last_state.max_evidence_age,
                                    };
                                    let request = IntraEncryptRequest {
                                        txid: req.txid,
                                        sealed_enc_request: req.sealed_enc_request,
                                        tx_inputs,
                                        info,
                                        account,
                                    };
                                    let response = self.enclave.process_request(
                                        IntraEnclaveRequest::Encrypt(Box::new(request)),
                                    );
                                    match response {
                                        Ok(IntraEnclaveResponseOk::Encrypt(obftx)) => Ok(obftx),
                                        Ok(_) => {
                                            log::error!("unexpected response");
                                            Err(chain_tx_validation::Error::EnclaveRejected)
                                        }
                                        Err(e) => Err(e),
                                    }
                                }
                                None => {
                                    log::error!("can not find last app state");
                                    Err(chain_tx_validation::Error::EnclaveRejected)
                                }
                            }
                        };
                        EnclaveResponse::EncryptTx(result)
                    }
                    Err(e) => {
                        log::error!("unknown request / failed to decode: {}", e);
                        EnclaveResponse::UnknownRequest
                    }
                };
                if let Err(err) = resp.write_to(&mut self.socket_to_enclave) {
                    log::error!("Error writing back tx-query response: {}", err);
                }
            }
        }
    }
}
