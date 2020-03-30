use crate::app::ChainNodeState;
use crate::enclave_bridge::real::enclave_u::encrypt_tx;
use chain_core::tx::data::TxId;
use chain_storage::ReadOnlyStorage;
use chain_tx_validation::ChainInfo;
use enclave_protocol::IntraEnclaveRequest;
use enclave_protocol::{EnclaveRequest, EnclaveResponse, IntraEncryptRequest, FLAGS};
use parity_scale_codec::{Decode, Encode};
use sgx_urts::SgxEnclave;
use std::sync::mpsc::Sender;
use zmq::{Context, Error, Socket, REP};

pub struct TxValidationServer {
    socket: Socket,
    enclave: SgxEnclave,
    storage: ReadOnlyStorage,
    network_id: u8,
    start_signal: Sender<()>,
}

impl TxValidationServer {
    pub fn new(
        connection_str: &str,
        enclave: SgxEnclave,
        storage: ReadOnlyStorage,
        network_id: u8,
        start_signal: Sender<()>,
    ) -> Result<TxValidationServer, Error> {
        let ctx = Context::new();
        let socket = ctx.socket(REP)?;
        socket.bind(connection_str)?;

        Ok(TxValidationServer {
            socket,
            enclave,
            storage,
            network_id,
            start_signal,
        })
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

    pub fn execute(&mut self) {
        log::info!("running zmq server");
        self.start_signal.send(()).unwrap();
        loop {
            if let Ok(msg) = self.socket.recv_bytes(FLAGS) {
                log::debug!("received a message");
                let mcmd = EnclaveRequest::decode(&mut msg.as_slice());
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
                                    // TODO: fee in enclave?
                                    // FIXME: staked state not in request, but looked up?
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
                                        unbonding_period: last_state
                                            .top_level
                                            .network_params
                                            .get_unbonding_period(),
                                    };
                                    let request = IntraEncryptRequest {
                                        txid: req.txid,
                                        sealed_enc_request: req.sealed_enc_request,
                                        tx_inputs,
                                        info,
                                    };
                                    encrypt_tx(
                                        self.enclave.geteid(),
                                        IntraEnclaveRequest::Encrypt(Box::new(request)),
                                    )
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
                let response = resp.encode();
                self.socket
                    .send(response, FLAGS)
                    .expect("reply sending failed");
            }
        }
    }
}
