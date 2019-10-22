#![crate_name = "txqueryenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(proc_macro_hygiene)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use sgx_rand::*;
use sgx_types::*;

use chain_core::tx::{
    data::{input::TxoIndex, TxId},
    TransactionId, TxEnclaveAux,
};
use enclave_protocol::{
    DecryptionRequest, DecryptionRequestBody, DecryptionResponse, EnclaveRequest, EnclaveResponse,
    EncryptionRequest, EncryptionResponse, QueryEncryptRequest, TxQueryInitRequest,
    TxQueryInitResponse, ENCRYPTION_REQUEST_SIZE,
};
use enclave_t_common::check_unseal;
use parity_scale_codec::{Decode, Encode};
use secp256k1::Secp256k1;
use sgx_tseal::SgxSealedData;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::prelude::v1::*;
use std::time::Duration;
use std::vec::Vec;

/// functionality related to remote attestation (RA)
mod attest;
/// utility for generating the TLS cert with the RA payload
mod cert;

const TIMEOUT_SEC: u64 = 5;

extern "C" {
    pub fn ocall_encrypt_request(
        ret_val: *mut sgx_status_t,
        request: *const u8,
        request_len: u32,
        response: *mut u8,
        response_len: u32,
    ) -> sgx_status_t;

    pub fn ocall_get_txs(
        ret_val: *mut sgx_status_t,
        txids: *const u8,
        txids_len: u32,
        txs: *mut u8,
        txs_len: u32,
    ) -> sgx_status_t;
}

fn process_decryption_request(body: &DecryptionRequestBody) -> Option<DecryptionResponse> {
    let txids_enc = body.txs.encode();
    // TODO: check tx size
    let mut inputs_buf = vec![0u8; body.txs.len() * 8000];
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let result = unsafe {
        ocall_get_txs(
            &mut rt as *mut sgx_status_t,
            txids_enc.as_ptr(),
            txids_enc.len() as u32,
            inputs_buf.as_mut_ptr(),
            inputs_buf.len() as u32,
        )
    };
    if result != sgx_status_t::SGX_SUCCESS || rt != sgx_status_t::SGX_SUCCESS {
        return None;
    }
    let inputs_enc: Result<Vec<Vec<u8>>, parity_scale_codec::Error> =
        Decode::decode(&mut inputs_buf.as_slice());
    if let Ok(inputs) = inputs_enc {
        check_unseal(
            Some(body.view_key),
            true,
            body.txs.iter().map(|x| *x),
            inputs,
        )
        .map(|txs| DecryptionResponse { txs })
    } else {
        None
    }
}

fn handle_decryption_request(
    tls: &mut rustls::Stream<rustls::ServerSession, TcpStream>,
    mut plain: Vec<u8>,
) -> sgx_status_t {
    let mut challenge = [0u8; 32];
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut challenge);
    if let Err(_) = tls.write(&TxQueryInitResponse::DecryptChallenge(challenge).encode()[..]) {
        let _ = tls.sock.shutdown(Shutdown::Both);
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    match tls.read(&mut plain) {
        Ok(_) => {
            if let Ok(dr) = DecryptionRequest::decode(&mut plain.as_slice()) {
                if dr
                    .verify(&Secp256k1::verification_only(), challenge)
                    .is_err()
                {
                    let _ = tls.sock.shutdown(Shutdown::Both);
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                if let Some(reply) = process_decryption_request(&dr.body) {
                    let _ = tls.write(&reply.encode());
                } else {
                    let _ = tls.sock.shutdown(Shutdown::Both);
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
            } else {
                let _ = tls.sock.shutdown(Shutdown::Both);
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
        Err(_) => {
            // println!("Error in read_to_end: {:?}", e);
            let _ = tls.sock.shutdown(Shutdown::Both);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    sgx_status_t::SGX_SUCCESS
}

fn get_sealed_request(req: &EncryptionRequest, txid: &TxId) -> Option<Vec<u8>> {
    let to_seal = req.encode();
    let sealing_result = SgxSealedData::<[u8]>::seal_data(txid, &to_seal);
    let sealed_data = match sealing_result {
        Ok(x) => x,
        Err(_ret) => {
            return None;
        }
    };
    let sealed_log_size = SgxSealedData::<[u8]>::calc_raw_sealed_data_size(
        sealed_data.get_add_mac_txt_len(),
        sealed_data.get_encrypt_txt_len(),
    ) as usize;
    let mut sealed_log: Vec<u8> = vec![0u8; sealed_log_size];

    unsafe {
        let sealed_r = sealed_data.to_raw_sealed_data_t(
            sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t,
            sealed_log_size as u32,
        );
        if sealed_r.is_none() {
            return None;
        }
    }
    Some(sealed_log)
}

fn construct_request(req: &EncryptionRequest) -> Option<QueryEncryptRequest> {
    let (txid, sealed, tx_inputs) = match req {
        EncryptionRequest::TransferTx(tx, _) => {
            let txid = tx.id();
            let sealed = get_sealed_request(&req, &txid);
            let tx_inputs = Some(tx.inputs.clone());
            (txid, sealed, tx_inputs)
        }
        EncryptionRequest::DepositStake(tx, _) => {
            let txid = tx.id();
            let sealed = get_sealed_request(&req, &txid);
            let tx_inputs = Some(tx.inputs.clone());
            (txid, sealed, tx_inputs)
        }
        EncryptionRequest::WithdrawStake(tx, _, _) => {
            let txid = tx.id();
            let sealed = get_sealed_request(&req, &txid);
            (txid, sealed, None)
        }
    };
    sealed.map(|sealed_enc_request| QueryEncryptRequest {
        txid,
        sealed_enc_request,
        tx_inputs,
    })
}

fn handle_encryption_request(
    tls: &mut rustls::Stream<rustls::ServerSession, TcpStream>,
    req: EncryptionRequest,
) -> sgx_status_t {
    let request = construct_request(&req);
    match request {
        None => {
            let _ = tls.sock.shutdown(Shutdown::Both);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
        Some(qreq) => {
            let req_enc = EnclaveRequest::EncryptTx(Box::new(qreq)).encode();
            let mut result_buf = vec![0u8; req_enc.len()];
            let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
            let result = unsafe {
                ocall_encrypt_request(
                    &mut rt as *mut sgx_status_t,
                    req_enc.as_ptr(),
                    req_enc.len() as u32,
                    result_buf.as_mut_ptr(),
                    result_buf.len() as u32,
                )
            };
            if result != sgx_status_t::SGX_SUCCESS {
                return result;
            }
            if rt != sgx_status_t::SGX_SUCCESS {
                return rt;
            }
            match EnclaveResponse::decode(&mut result_buf.as_slice()) {
                Ok(EnclaveResponse::EncryptTx(Ok(payload))) => {
                    let tx = match req {
                        EncryptionRequest::TransferTx(tx, _) => {
                            let inputs = tx.inputs;
                            let no_of_outputs = tx.outputs.len() as TxoIndex;
                            TxEnclaveAux::TransferTx {
                                inputs,
                                no_of_outputs,
                                payload,
                            }
                        }
                        EncryptionRequest::DepositStake(tx, _) => {
                            TxEnclaveAux::DepositStakeTx { tx, payload }
                        }
                        EncryptionRequest::WithdrawStake(tx, _, witness) => {
                            let no_of_outputs = tx.outputs.len() as TxoIndex;
                            TxEnclaveAux::WithdrawUnbondedStakeTx {
                                no_of_outputs,
                                witness,
                                payload,
                            }
                        }
                    };
                    let _ = tls.write(&EncryptionResponse { tx }.encode());
                    sgx_status_t::SGX_SUCCESS
                }
                _ => {
                    // TODO: returning validation error
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
            }
        }
    }
}

/// The main routine:
/// 0. is passed in the TCP client socket
/// 1. creates a TLS server session
/// either from a cached configuration / cert
/// or generates a fresh one (quite involved, as it involves the remote attestation)
/// 2. sends a random payload/challenge to the client
/// 3. (client replies with a signed decryption request that includes the challenge)
/// 4. verifies the decryption request
/// 5. if OK, it processes it:
/// - asks the tx-validation enclave to send back sealed transaction payloads
/// - unseales the transactions and checks if the metadata contains the view key in the request
/// - if so, it includes the transaction in the reply and sends it back
#[no_mangle]
pub extern "C" fn run_server(socket_fd: c_int) -> sgx_status_t {
    let mut sess = rustls::ServerSession::new(&attest::get_tls_config());
    let mut conn = TcpStream::new(socket_fd).unwrap();
    let _ = conn.set_read_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
    let _ = conn.set_write_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
    let mut tls = rustls::Stream::new(&mut sess, &mut conn);
    let mut plain = vec![0; ENCRYPTION_REQUEST_SIZE];
    match tls.read(&mut plain) {
        Ok(_) => match TxQueryInitRequest::decode(&mut plain.as_slice()) {
            Ok(TxQueryInitRequest::Encrypt(req)) => handle_encryption_request(&mut tls, *req),
            Ok(TxQueryInitRequest::DecryptChallenge) => handle_decryption_request(&mut tls, plain),
            _ => {
                let _ = conn.shutdown(Shutdown::Both);
                sgx_status_t::SGX_ERROR_INVALID_PARAMETER
            }
        },
        Err(_) => {
            // println!("Error in read_to_end: {:?}", e);
            let _ = conn.shutdown(Shutdown::Both);
            sgx_status_t::SGX_ERROR_UNEXPECTED
        }
    }
}
