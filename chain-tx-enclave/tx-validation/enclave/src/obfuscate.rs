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

pub(crate) fn decrypt(tx: &TxObfuscated) -> Result<PlainTxAux, ()> {
    let key = GenericArray::clone_from_slice(&MOCK_KEY);
    let aead = Aes128GcmSiv::new(key);
    let nonce = GenericArray::from_slice(&tx.init_vector);
    let plaintext = aead.decrypt(nonce, tx).map_err(|_| ())?;
    let result = PlainTxAux::decode(&mut plaintext.as_ref());
    result.map_err(|_| ())
}

#[inline]
fn unseal_request(request: &mut IntraEncryptRequest) -> Option<EncryptionRequest> {
    let opt = unsafe {
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
        Err(_) => {
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
        Err(_) => None,
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
            Ok(Ok(IntraEnclaveResponseOk::Encrypt(Box::new(otx))))
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
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
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
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
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
                _ => {
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
            }
        }
        (_, _) => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }
}
