use enclave_u_common::{META_KEYSPACE, TX_KEYSPACE};
use log::{debug, info};
use parity_scale_codec::{Decode, Encode};
use sgx_types::sgx_status_t;
use sled::Tree;
use std::sync::{Arc, Mutex};
use zmq::{Context, Error, Socket, REP};

use chain_core::common::H256;
use chain_core::state::account::{DepositBondTx, StakedState};
use chain_core::tx::{data::TxId, fee::Fee, TxEnclaveAux, TxObfuscated};
use chain_core::ChainInfo;
use enclave_protocol::{
    is_basic_valid_tx_request, EnclaveRequest, EnclaveResponse, IntraEnclaveRequest,
    IntraEnclaveResponseOk, IntraEncryptRequest, FLAGS,
};

use crate::TxValidationEnclave;

const LAST_APP_HASH_KEY: &[u8] = b"last_apphash";
const LAST_CHAIN_INFO_KEY: &[u8] = b"chain_info";
static ENCLAVE_FILE: &str = "tx_validation_enclave.signed.so";

pub struct TxValidationApp {
    enclave: TxValidationEnclave,
    txdb: Tree,
    metadb: Tree,
    info: Option<ChainInfo>,
}

impl TxValidationApp {
    pub fn with_path(path: &str) -> Result<Self, String> {
        let db = sled::open(path).expect("failed to open a storage path");
        let metadb = db
            .open_tree(META_KEYSPACE)
            .expect("failed to open a meta keyspace");
        let txdb = db
            .open_tree(TX_KEYSPACE)
            .expect("failed to open a tx keyspace");
        let enclave =
            TxValidationEnclave::new(ENCLAVE_FILE, true).expect("init tx validation enclave");
        Self::new(enclave, txdb, metadb)
    }

    pub fn new(
        enclave: TxValidationEnclave,
        txdb: Tree,
        metadb: Tree,
    ) -> Result<TxValidationApp, String> {
        let info = match metadb.get(LAST_CHAIN_INFO_KEY) {
            Ok(Some(bytes)) => Some(
                ChainInfo::decode(&mut bytes.as_ref())
                    .map_err(|err| format!("stored chain info corrupted: {}", err.to_string()))?,
            ),
            Ok(None) => None,
            Err(err) => return Err(format!("load chain_info failed: {}", err.to_string())),
        };

        Ok(TxValidationApp {
            enclave,
            txdb,
            metadb,
            info,
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

    fn flush_all(&mut self) -> Result<usize, sled::Error> {
        let _ = self.txdb.flush()?;
        self.metadb.flush()
    }

    pub fn execute(&mut self, cmd: EnclaveRequest) -> EnclaveResponse {
        match cmd {
            EnclaveRequest::CheckChain {
                chain_hex_id,
                last_app_hash,
            } => {
                debug!("check chain");
                match self.metadb.get(LAST_APP_HASH_KEY) {
                    Err(_) => EnclaveResponse::CheckChain(Err(None)),
                    Ok(s) => {
                        let ss = s.map(|stored| {
                            let mut app_hash = [0u8; 32];
                            app_hash.copy_from_slice(&stored);
                            app_hash
                        });
                        if last_app_hash == ss {
                            EnclaveResponse::CheckChain(check_initchain(
                                &self.enclave,
                                chain_hex_id,
                                ss,
                            ))
                        } else {
                            EnclaveResponse::CheckChain(Err(ss))
                        }
                    }
                }
            }
            EnclaveRequest::EndBlock => {
                EnclaveResponse::EndBlock(end_block(&self.enclave, IntraEnclaveRequest::EndBlock))
            }
            EnclaveRequest::CommitBlock { app_hash, info } => {
                let _ = self.metadb.insert(LAST_APP_HASH_KEY, &app_hash);
                let _ = self.metadb.insert(LAST_CHAIN_INFO_KEY, &info.encode()[..]);
                if self.flush_all().is_ok() {
                    self.info = Some(info);
                    EnclaveResponse::CommitBlock(Ok(()))
                } else {
                    EnclaveResponse::CommitBlock(Err(()))
                }
            }
            EnclaveRequest::VerifyTx(req) => {
                let chid = req.info.chain_hex_id;
                let mtxins = self.lookup(&req.tx);
                if is_basic_valid_tx_request(&req, &mtxins, chid).is_err() {
                    EnclaveResponse::UnknownRequest
                } else {
                    EnclaveResponse::VerifyTx(check_tx(
                        &self.enclave,
                        IntraEnclaveRequest::ValidateTx {
                            request: req,
                            tx_inputs: mtxins,
                        },
                        &mut self.txdb,
                    ))
                }
            }
            EnclaveRequest::GetSealedTxData { txids } => {
                EnclaveResponse::GetSealedTxData(self.lookup_txids(txids.iter().copied()))
            }
            EnclaveRequest::EncryptTx(req) => {
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
                            &self.enclave,
                            IntraEnclaveRequest::Encrypt(Box::new(request)),
                        )
                    }
                    _ => Err(chain_tx_validation::Error::EnclaveRejected),
                };
                EnclaveResponse::EncryptTx(result)
            }
        }
    }
}

pub struct TxValidationServer {
    socket: Socket,
    app: Arc<Mutex<TxValidationApp>>,
}

impl TxValidationServer {
    pub fn new(
        connection_str: &str,
        app: Arc<Mutex<TxValidationApp>>,
    ) -> Result<TxValidationServer, Error> {
        let ctx = Context::new();
        let socket = ctx.socket(REP)?;
        socket.bind(connection_str)?;

        Ok(TxValidationServer { socket, app })
    }

    pub fn execute(&mut self) {
        info!("running zmq server");
        loop {
            if let Ok(msg) = self.socket.recv_bytes(FLAGS) {
                debug!("received a message");
                let mcmd = EnclaveRequest::decode(&mut msg.as_slice());
                let resp = match mcmd {
                    Ok(cmd) => self.app.lock().unwrap().execute(cmd),
                    Err(e) => {
                        debug!("unknown request / failed to decode: {}", e);
                        EnclaveResponse::UnknownRequest
                    }
                };
                self.socket
                    .send(resp.encode(), FLAGS)
                    .expect("reply sending failed");
            }
        }
    }
}

fn encrypt_tx(
    enclave: &TxValidationEnclave,
    request: IntraEnclaveRequest,
) -> Result<TxObfuscated, chain_tx_validation::Error> {
    if let Ok(response) = enclave.ecall_check_tx(&request) {
        match response {
            Ok(IntraEnclaveResponseOk::Encrypt(obftx)) => Ok(obftx),
            Err(e) => Err(e),
            _ => Err(chain_tx_validation::Error::EnclaveRejected),
        }
    } else {
        Err(chain_tx_validation::Error::EnclaveRejected)
    }
}

fn check_tx(
    enclave: &TxValidationEnclave,
    request: IntraEnclaveRequest,
    txdb: &mut Tree,
) -> Result<(Fee, Option<StakedState>), chain_tx_validation::Error> {
    if let Ok(response) = enclave.ecall_check_tx(&request) {
        match (request, response) {
            (
                IntraEnclaveRequest::ValidateTx { request, .. },
                Ok(IntraEnclaveResponseOk::TxWithOutputs {
                    paid_fee,
                    sealed_tx,
                }),
            ) => {
                let _ = txdb
                    .insert(&request.tx.tx_id(), sealed_tx)
                    .map_err(|_| chain_tx_validation::Error::IoError)?;
                if let Some(mut account) = request.account {
                    account.withdraw();
                    Ok((paid_fee, Some(account)))
                } else {
                    Ok((paid_fee, None))
                }
            }
            (
                IntraEnclaveRequest::ValidateTx { request, .. },
                Ok(IntraEnclaveResponseOk::DepositStakeTx { input_coins }),
            ) => {
                let deposit_amount =
                    (input_coins - request.info.min_fee_computed.to_coin()).expect("init");
                let account = match (request.account, request.tx) {
                    (Some(mut a), _) => {
                        a.deposit(deposit_amount);
                        Some(a)
                    }
                    (
                        None,
                        TxEnclaveAux::DepositStakeTx {
                            tx:
                                DepositBondTx {
                                    to_staked_account, ..
                                },
                            ..
                        },
                    ) => Some(StakedState::new_init_bonded(
                        deposit_amount,
                        request.info.previous_block_time,
                        to_staked_account,
                        None,
                    )),
                    (_, _) => unreachable!("one shouldn't call this with other variants"),
                };
                let fee = request.info.min_fee_computed;
                Ok((fee, account))
            }
            (_, Err(e)) => Err(e),
            (_, _) => Err(chain_tx_validation::Error::EnclaveRejected),
        }
    } else {
        Err(chain_tx_validation::Error::EnclaveRejected)
    }
}

fn end_block(
    enclave: &TxValidationEnclave,
    request: IntraEnclaveRequest,
) -> Result<Option<Box<[u8; 256]>>, ()> {
    if let Ok(response) = enclave.ecall_check_tx(&request) {
        match response {
            Ok(IntraEnclaveResponseOk::EndBlock(maybe_filter)) => Ok(maybe_filter),
            _ => Err(()),
        }
    } else {
        Err(())
    }
}

fn check_initchain(
    enclave: &TxValidationEnclave,
    chain_hex_id: u8,
    last_app_hash: Option<H256>,
) -> Result<(), Option<H256>> {
    let retval = enclave.ecall_initchain(chain_hex_id);
    if retval == sgx_status_t::SGX_SUCCESS {
        Ok(())
    } else {
        Err(last_app_hash)
    }
}
