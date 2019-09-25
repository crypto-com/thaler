use crate::enclave_u::{check_initchain, check_tx, end_block, get_token_arr, store_token};
use chain_core::state::account::DepositBondTx;
use chain_core::tx::data::TxId;
use chain_core::tx::TxAux;
use enclave_protocol::IntraEnclaveRequest;
use enclave_protocol::{is_basic_valid_tx_request, EnclaveRequest, EnclaveResponse, FLAGS};
use log::{debug, info};
use parity_scale_codec::{Decode, Encode};
use sgx_urts::SgxEnclave;
use sled::Tree;
use zmq::{Context, Error, Socket, REP};

pub struct TxValidationServer {
    socket: Socket,
    enclave: SgxEnclave,
    txdb: Tree,
    metadb: Tree,
}

impl TxValidationServer {
    pub fn new(
        connection_str: &str,
        enclave: SgxEnclave,
        txdb: Tree,
        metadb: Tree,
    ) -> Result<TxValidationServer, Error> {
        let ctx = Context::new();
        let socket = ctx.socket(REP)?;
        socket.bind(connection_str)?;
        Ok(TxValidationServer {
            socket,
            enclave,
            txdb,
            metadb,
        })
    }

    fn lookup_txids<I>(&self, inputs: I) -> Option<Vec<Vec<u8>>>
    where
        I: IntoIterator<Item = TxId> + ExactSizeIterator,
    {
        let mut result = Vec::with_capacity(inputs.len());
        for input in inputs.into_iter() {
            if let Ok(Some(txin)) = self.txdb.get(input) {
                result.push(txin.to_vec());
            } else {
                return None;
            }
        }
        Some(result)
    }

    fn lookup(&self, tx: &TxAux) -> Option<Vec<Vec<u8>>> {
        match tx {
            TxAux::TransferTx { inputs, .. } => self.lookup_txids(inputs.iter().map(|x| x.id)),
            TxAux::DepositStakeTx {
                tx: DepositBondTx { inputs, .. },
                ..
            } => self.lookup_txids(inputs.iter().map(|x| x.id)),
            _ => None,
        }
    }

    pub fn execute(&mut self) {
        info!("running zmq server");
        loop {
            if let Ok(msg) = self.socket.recv_bytes(FLAGS) {
                debug!("received a message");
                let mcmd = EnclaveRequest::decode(&mut msg.as_slice());
                let resp = match mcmd {
                    Ok(EnclaveRequest::CheckChain {
                        chain_hex_id,
                        last_app_hash,
                    }) => {
                        debug!("check chain");
                        match self.txdb.get(b"last_apphash") {
                            Err(_) => EnclaveResponse::CheckChain(Err(None)),
                            Ok(s) => {
                                let ss = s.map(|stored| {
                                    let mut app_hash = [0u8; 32];
                                    app_hash.copy_from_slice(&stored);
                                    app_hash
                                });
                                if last_app_hash == ss {
                                    EnclaveResponse::CheckChain(check_initchain(
                                        self.enclave.geteid(),
                                        chain_hex_id,
                                        ss,
                                    ))
                                } else {
                                    EnclaveResponse::CheckChain(Err(ss))
                                }
                            }
                        }
                    }
                    Ok(EnclaveRequest::EndBlock) => EnclaveResponse::EndBlock(end_block(
                        self.enclave.geteid(),
                        IntraEnclaveRequest::EndBlock,
                    )),
                    Ok(EnclaveRequest::CommitBlock { app_hash }) => {
                        let _ = self.txdb.insert(b"last_apphash", &app_hash);
                        if let Ok(_) = self.txdb.flush() {
                            EnclaveResponse::CommitBlock(Ok(()))
                        } else {
                            EnclaveResponse::CommitBlock(Err(()))
                        }
                    }
                    Ok(EnclaveRequest::VerifyTx(req)) => {
                        let chid = req.info.chain_hex_id;
                        let mtxins = self.lookup(&req.tx);
                        if is_basic_valid_tx_request(&req, &mtxins, chid).is_err() {
                            EnclaveResponse::UnsupportedTxType
                        } else {
                            EnclaveResponse::VerifyTx(check_tx(
                                self.enclave.geteid(),
                                IntraEnclaveRequest::ValidateTx {
                                    request: req,
                                    tx_inputs: mtxins,
                                },
                                &mut self.txdb,
                            ))
                        }
                    }
                    Ok(EnclaveRequest::GetCachedLaunchToken { enclave_metaname }) => {
                        EnclaveResponse::GetCachedLaunchToken(get_token_arr(
                            &self.metadb,
                            &enclave_metaname,
                        ))
                    }
                    Ok(EnclaveRequest::UpdateCachedLaunchToken {
                        enclave_metaname,
                        token,
                    }) => EnclaveResponse::UpdateCachedLaunchToken(store_token(
                        &mut self.metadb,
                        &enclave_metaname,
                        token.to_vec(),
                    )),
                    Ok(EnclaveRequest::GetSealedTxData { txids }) => {
                        EnclaveResponse::GetSealedTxData(
                            self.lookup_txids(txids.iter().map(|x| *x)),
                        )
                    }
                    Err(e) => {
                        debug!("unknown request / failed to decode: {}", e);
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
