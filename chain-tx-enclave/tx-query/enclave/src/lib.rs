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

use enclave_protocol::{DecryptionRequest, DecryptionRequestBody, DecryptionResponse};
use enclave_t_common::check_unseal;
use parity_scale_codec::{Decode, Encode};
use secp256k1::Secp256k1;
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
    pub fn ocall_get_txs(
        ret_val: *mut sgx_status_t,
        txids: *const u8,
        txids_len: u32,
        txs: *mut u8,
        txs_len: u32,
    ) -> sgx_status_t;
}

fn process_request(body: &DecryptionRequestBody) -> Option<DecryptionResponse> {
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
    let mut challenge = [0u8; 32];
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut challenge);
    if let Err(_) = tls.write(&challenge[..]) {
        let _ = conn.shutdown(Shutdown::Both);
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    let mut plain = vec![0; 1024];
    match tls.read(&mut plain) {
        Ok(_) => {
            if let Ok(dr) = DecryptionRequest::decode(&mut plain.as_slice()) {
                if dr
                    .verify(&Secp256k1::verification_only(), challenge)
                    .is_err()
                {
                    let _ = conn.shutdown(Shutdown::Both);
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                if let Some(reply) = process_request(&dr.body) {
                    let _ = tls.write(&reply.encode());
                } else {
                    let _ = conn.shutdown(Shutdown::Both);
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
            } else {
                let _ = conn.shutdown(Shutdown::Both);
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
        Err(_) => {
            // println!("Error in read_to_end: {:?}", e);
            let _ = conn.shutdown(Shutdown::Both);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    sgx_status_t::SGX_SUCCESS
}
