use crate::validate::write_back_response;
use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes128GcmSiv;
use chain_core::tx::TransactionId;
use chain_core::tx::{PlainTxAux, TxObfuscated, TxToObfuscate};
use chain_tx_validation::{
    verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw_core,
    witness::verify_tx_recover_address,
};
use enclave_macro::mock_key;
use enclave_protocol::{EncryptionRequest, IntraEncryptRequest};
use enclave_protocol::{IntraEnclaveResponse, IntraEnclaveResponseOk};
use enclave_t_common::check_unseal;
use parity_scale_codec::Decode;
#[cfg(feature = "sgx-test")]
use parity_scale_codec::Encode;
use sgx_rand::{os::SgxRng, Rng};
use sgx_tseal::SgxSealedData;
use sgx_types::{sgx_sealed_data_t, sgx_status_t};
use std::prelude::v1::Box;
use zeroize::Zeroize;

const MOCK_KEY: [u8; 16] = mock_key!();

pub(crate) fn encrypt(tx: TxToObfuscate) -> TxObfuscated {
    let mut init_vector = [0u8; 12];
    let mut os_rng = SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut init_vector);
    let key = GenericArray::clone_from_slice(&MOCK_KEY);
    let aead = Aes128GcmSiv::new(key);
    let nonce = GenericArray::from_slice(&init_vector);
    let ciphertext = aead.encrypt(nonce, &tx).expect("encryption failure!");
    TxObfuscated {
        key_from: -1,
        init_vector,
        txpayload: ciphertext,
        txid: tx.txid,
    }
}

#[cfg(not(feature = "sgx-test"))]
#[no_mangle]
pub extern "C" fn ecall_test_encrypt(
    _enc_request: *const u8,
    _enc_request_len: usize,
    _response_buf: *mut u8,
    _response_len: u32,
) -> sgx_status_t {
    // only for testing
    sgx_status_t::SGX_ERROR_INVALID_FUNCTION
}

#[cfg(feature = "sgx-test")]
#[no_mangle]
pub extern "C" fn ecall_test_encrypt(
    enc_request: *const u8,
    enc_request_len: usize,
    response_buf: *mut u8,
    response_len: u32,
) -> sgx_status_t {
    // direct encryption (without any checks) for testing only
    let mut payload = unsafe { std::slice::from_raw_parts(enc_request, enc_request_len) };
    let req = EncryptionRequest::decode(&mut payload);
    let otx = match req {
        Ok(EncryptionRequest::TransferTx(tx, witness)) => {
            let txid = tx.id();
            encrypt(
                TxToObfuscate::from(PlainTxAux::TransferTx(tx, witness), txid)
                    .expect("construct plain payload"),
            )
        }
        Ok(EncryptionRequest::DepositStake(tx, witness)) => {
            let txid = tx.id();
            encrypt(
                TxToObfuscate::from(PlainTxAux::DepositStakeTx(witness), txid)
                    .expect("construct plain payload"),
            )
        }
        Ok(EncryptionRequest::WithdrawStake(tx, _account, witness)) => {
            let txid = tx.id();
            encrypt(
                TxToObfuscate::from(PlainTxAux::WithdrawUnbondedStakeTx(tx), txid)
                    .expect("construct plain payload"),
            )
        }
        _ => panic!("test input"),
    };
    let to_copy = otx.encode();
    let resp_len = to_copy.len() as u32;
    if resp_len > 0 && resp_len <= response_len {
        unsafe {
            std::ptr::copy_nonoverlapping(to_copy.as_ptr(), response_buf, to_copy.len());
        }
        sgx_status_t::SGX_SUCCESS
    } else {
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    }
}

pub(crate) fn decrypt(tx: &TxObfuscated) -> Result<PlainTxAux, ()> {
    let key = GenericArray::clone_from_slice(&MOCK_KEY);
    let aead = Aes128GcmSiv::new(key);
    let nonce = GenericArray::from_slice(&tx.init_vector);
    let plaintext = aead.decrypt(nonce, tx).map_err(|_| ())?;
    let result = PlainTxAux::decode(&mut plaintext.as_slice());
    result.map_err(|_| ())
}

#[inline]
fn unseal_request(request: &mut IntraEncryptRequest) -> Option<EncryptionRequest> {
    let opt = unsafe {
        // TODO check alignment correctness
        #[allow(clippy::cast_ptr_alignment)]
        SgxSealedData::<[u8]>::from_raw_sealed_data_t(
            request.sealed_enc_request.as_mut_ptr() as *mut sgx_sealed_data_t,
            request.sealed_enc_request.len() as u32,
        )
    };
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return None;
        }
    };
    let result = sealed_data.unseal_data();
    let mut unsealed_data = match result {
        Ok(x) => x,
        Err(e) => {
            log::error!("unsal data failed: {:?}", e);
            return None;
        }
    };
    if unsealed_data.get_additional_txt() != request.txid {
        unsealed_data.decrypt.zeroize();
        return None;
    }
    let otx = EncryptionRequest::decode(&mut unsealed_data.get_decrypt_txt());
    match otx {
        Ok(o) => Some(o),
        Err(e) => {
            log::error!("decode encryption request failed: {:?}", e);
            None
        }
    }
}

#[inline]
fn construct_response(
    result: Result<(), chain_tx_validation::Error>,
    to_obfuscate_tx: TxToObfuscate,
) -> Result<IntraEnclaveResponse, sgx_status_t> {
    match result {
        Err(e) => Ok(Err(e)),
        Ok(_) => {
            let otx = encrypt(to_obfuscate_tx);
            Ok(Ok(IntraEnclaveResponseOk::Encrypt(otx)))
        }
    }
}

#[inline]
pub(crate) fn handle_encrypt_request(
    mut request: Box<IntraEncryptRequest>,
    response_buf: *mut u8,
    response_len: u32,
) -> sgx_status_t {
    match (unseal_request(&mut request), request.tx_inputs) {
        (Some(EncryptionRequest::TransferTx(tx, witness)), Some(sealed_inputs)) => {
            let unsealed_inputs =
                check_unseal(None, false, tx.inputs.iter().map(|x| x.id), sealed_inputs);
            if let Some(inputs) = unsealed_inputs {
                let result = verify_transfer(&tx, &witness, request.info, inputs);
                let txid = tx.id();
                let response = construct_response(
                    result.map(|_| ()),
                    TxToObfuscate::from(PlainTxAux::TransferTx(tx, witness), txid)
                        .expect("construct plain payload"),
                );
                write_back_response(response, response_buf, response_len)
            } else {
                sgx_status_t::SGX_ERROR_INVALID_PARAMETER
            }
        }
        (Some(EncryptionRequest::DepositStake(tx, witness)), Some(sealed_inputs)) => {
            let unsealed_inputs =
                check_unseal(None, false, tx.inputs.iter().map(|x| x.id), sealed_inputs);
            if let Some(inputs) = unsealed_inputs {
                let result = verify_bonded_deposit_core(&tx, &witness, request.info, inputs);
                let txid = tx.id();
                let response = construct_response(
                    result.map(|_| ()),
                    TxToObfuscate::from(PlainTxAux::DepositStakeTx(witness), txid)
                        .expect("construct plain payload"),
                );
                write_back_response(response, response_buf, response_len)
            } else {
                sgx_status_t::SGX_ERROR_INVALID_PARAMETER
            }
        }
        (Some(EncryptionRequest::WithdrawStake(tx, account, witness)), None) => {
            let txid = tx.id();
            let maddress = verify_tx_recover_address(&witness, &txid);
            match maddress {
                Ok(address) if address == account.address => {
                    let result = verify_unbonded_withdraw_core(&tx, request.info, &account);
                    let response = construct_response(
                        result.map(|_| ()),
                        TxToObfuscate::from(PlainTxAux::WithdrawUnbondedStakeTx(tx), txid)
                            .expect("construct plain payload"),
                    );
                    write_back_response(response, response_buf, response_len)
                }
                _ => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
            }
        }
        (_, _) => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    }
}
