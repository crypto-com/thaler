use crate::enclave_u::{check_initchain, check_tx, encrypt_tx, end_block};
use chain_core::state::account::DepositBondTx;
use chain_core::tx::data::TxId;
use chain_core::tx::TxEnclaveAux;
use chain_core::ChainInfo;
use enclave_protocol::IntraEnclaveRequest;
use enclave_protocol::{
    is_basic_valid_tx_request, EnclaveRequest, EnclaveResponse, IntraEncryptRequest, FLAGS,
};
use parity_scale_codec::{Decode, Encode};
use sgx_urts::SgxEnclave;
use sled::Tree;
use zmq::{Context, Error, Socket, REP};

pub struct TxValidationServer {
    socket: Socket,
    enclave: SgxEnclave,
    txdb: Tree,
    metadb: Tree,
    info: Option<ChainInfo>,
}

const LAST_APP_HASH_KEY: &[u8] = b"last_apphash";
const LAST_CHAIN_INFO_KEY: &[u8] = b"chain_info";

impl TxValidationServer {
    pub fn new(
        connection_str: &str,
        enclave: SgxEnclave,
        txdb: Tree,
        metadb: Tree,
    ) -> Result<TxValidationServer, Error> {
        match metadb.get(LAST_CHAIN_INFO_KEY) {
            Err(e) => {
                log::error!("get last chain info failed: {:?}", e);
                Err(Error::EFAULT)
            }
            Ok(s) => {
                let info = s.map(|stored| {
                    ChainInfo::decode(&mut stored.as_ref()).expect("stored chain info corrupted")
                });
                let ctx = Context::new();
                let socket = ctx.socket(REP)?;
                socket.bind(connection_str)?;

                Ok(TxValidationServer {
                    socket,
                    enclave,
                    txdb,
                    metadb,
                    info,
                })
            }
        }
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

    fn lookup(&self, tx: &TxEnclaveAux) -> Option<Vec<Vec<u8>>> {
        match tx {
            TxEnclaveAux::TransferTx { inputs, .. } => {
                self.lookup_txids(inputs.iter().map(|x| x.id))
            }
            TxEnclaveAux::DepositStakeTx {
                tx: DepositBondTx { inputs, .. },
                ..
            } => self.lookup_txids(inputs.iter().map(|x| x.id)),
            _ => None,
        }
    }

    pub fn flush_all(&mut self) -> Result<usize, sled::Error> {
        let _ = self.txdb.flush()?;
        self.metadb.flush()
    }

    pub fn execute(&mut self) {
        log::info!("running zmq server");
        loop {
            if let Ok(msg) = self.socket.recv_bytes(FLAGS) {
                log::debug!("received a message");
                let mcmd = EnclaveRequest::decode(&mut msg.as_slice());
                let resp = match mcmd {
                    Ok(EnclaveRequest::CheckChain {
                        chain_hex_id,
                        last_app_hash,
                    }) => {
                        log::debug!("check chain");
                        match self.metadb.get(LAST_APP_HASH_KEY) {
                            Err(e) => {
                                log::error!("get last app hash failed: {:?}", e);
                                EnclaveResponse::CheckChain(Err(None))
                            }
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
                                    log::error!("app hash not match");
                                    EnclaveResponse::CheckChain(Err(ss))
                                }
                            }
                        }
                    }
                    Ok(EnclaveRequest::EndBlock) => EnclaveResponse::EndBlock(end_block(
                        self.enclave.geteid(),
                        IntraEnclaveRequest::EndBlock,
                    )),
                    Ok(EnclaveRequest::CommitBlock { app_hash, info }) => {
                        let _ = self.metadb.insert(LAST_APP_HASH_KEY, &app_hash);
                        let _ = self.metadb.insert(LAST_CHAIN_INFO_KEY, &info.encode()[..]);
                        if let Ok(_) = self.flush_all() {
                            self.info = Some(info);
                            EnclaveResponse::CommitBlock(Ok(()))
                        } else {
                            log::error!("flush data failed when commit block");
                            EnclaveResponse::CommitBlock(Err(()))
                        }
                    }
                    Ok(EnclaveRequest::VerifyTx(req)) => {
                        let chid = req.info.chain_hex_id;
                        let mtxins = self.lookup(&req.tx);
                        if let Err(e) = is_basic_valid_tx_request(&req, &mtxins, chid) {
                            log::error!("verify transaction failed: {}", e);
                            EnclaveResponse::UnknownRequest
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
                    Ok(EnclaveRequest::GetSealedTxData { txids }) => {
                        EnclaveResponse::GetSealedTxData(
                            self.lookup_txids(txids.iter().map(|x| *x)),
                        )
                    }
                    Ok(EnclaveRequest::EncryptTx(req)) => {
                        let result = match self.info {
                            Some(info) => {
                                let tx_inputs = match req.tx_inputs {
                                    Some(inputs) => self.lookup_txids(inputs.iter().map(|x| x.id)),
                                    _ => None,
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
                            _ => {
                                log::error!("can not find encrypted transaction");
                                Err(chain_tx_validation::Error::EnclaveRejected)
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
