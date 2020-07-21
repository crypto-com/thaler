// TODO: remove, as it's not required on newer nightly
use crate::sgx_module::write_response;
use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes128GcmSiv;
use chain_core::state::tendermint::BlockHeight;
use chain_core::tx::data::TxId;
use chain_core::tx::TransactionId;
use chain_core::tx::TxWithOutputs;
use chain_core::tx::{PlainTxAux, TxObfuscated, TxToObfuscate};
use chain_tx_validation::Error;
use chain_tx_validation::{
    verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw_core,
    witness::verify_tx_recover_address,
};
use enclave_macro::mock_key;
use enclave_protocol::{EncryptionRequest, IntraEncryptRequest};
use enclave_protocol::{IntraEnclaveResponse, IntraEnclaveResponseOk};
use enclave_utils::SealedData;
use parity_scale_codec::Decode;
use std::io::Write;
use std::prelude::v1::Box;
use zeroize::Zeroize;

/// this will be injected by TDBE connection
const MOCK_KEY: [u8; 16] = mock_key!();

pub(crate) fn encrypt(tx: TxToObfuscate) -> TxObfuscated {
    let init_vector: [u8; 12] = rand::random();
    let key = GenericArray::clone_from_slice(&MOCK_KEY);
    let aead = Aes128GcmSiv::new(&key);
    let nonce = GenericArray::from_slice(&init_vector);
    let ciphertext = aead.encrypt(nonce, &tx).expect("encryption failure!");
    TxObfuscated {
        key_from: BlockHeight::genesis(),
        init_vector,
        txpayload: ciphertext,
        txid: tx.txid,
    }
}

pub(crate) fn decrypt(tx: &TxObfuscated) -> Result<PlainTxAux, ()> {
    let key = GenericArray::clone_from_slice(&MOCK_KEY);
    let aead = Aes128GcmSiv::new(&key);
    let nonce = GenericArray::from_slice(&tx.init_vector);
    let plaintext = aead.decrypt(nonce, tx).map_err(|_| ())?;
    let result = PlainTxAux::decode(&mut plaintext.as_slice());
    result.map_err(|_| ())
}

#[inline]
fn unseal_request(request: &IntraEncryptRequest) -> Option<EncryptionRequest> {
    let sealed_data = SealedData::try_copy_from(&request.sealed_enc_request)?;
    if sealed_data.aes_data.additional_txt != request.txid {
        return None;
    }

    let result = sealed_data.unseal();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(e) => {
            log::error!("Error while unsealing sealed data: {:?}", e);
            return None;
        }
    };
    let otx = EncryptionRequest::decode(&mut unsealed_data.as_slice());
    match otx {
        Ok(o) => Some(o),
        Err(e) => {
            log::error!("decode encryption request failed: {:?}", e);
            None
        }
    }
}

#[inline]
pub fn check_unseal<I>(txids: I, sealed_logs: Vec<Vec<u8>>) -> Option<Vec<TxWithOutputs>>
where
    I: IntoIterator<Item = TxId> + ExactSizeIterator,
{
    let mut return_result = Vec::with_capacity(sealed_logs.len());

    for (txid, sealed_log) in txids.into_iter().zip(sealed_logs.into_iter()) {
        let sealed_data = SealedData::try_copy_from(&sealed_log)?;

        if sealed_data.aes_data.additional_txt != txid {
            return None;
        }

        let mut unsealed_data = sealed_data.unseal().ok()?;
        let otx = TxWithOutputs::decode(&mut unsealed_data.as_slice());
        if let Ok(tx) = otx {
            return_result.push(tx.clone());
        } else {
            return None;
        }

        unsealed_data.zeroize();
    }
    Some(return_result)
}

#[inline]
pub(crate) fn handle_encrypt_request<I: Write>(request: Box<IntraEncryptRequest>, output: &mut I) {
    match (unseal_request(&request), request.tx_inputs) {
        (Some(EncryptionRequest::TransferTx(tx, witness)), Some(sealed_inputs)) => {
            let unsealed_inputs = check_unseal(tx.inputs.iter().map(|x| x.id), sealed_inputs);
            if let Some(inputs) = unsealed_inputs {
                let result = verify_transfer(&tx, &witness, &request.info, inputs);
                let txid = tx.id();
                let response: IntraEnclaveResponse = result.map(|_| {
                    IntraEnclaveResponseOk::Encrypt(encrypt(
                        TxToObfuscate::from(PlainTxAux::TransferTx(tx, witness), txid)
                            .expect("construct plain payload"),
                    ))
                });
                write_response(response, output);
            } else {
                log::debug!("failed to unseal inputs");
                write_response(Err(Error::EnclaveRejected), output);
            }
        }
        (Some(EncryptionRequest::DepositStake(tx, witness)), Some(sealed_inputs)) => {
            let unsealed_inputs = check_unseal(tx.inputs.iter().map(|x| x.id), sealed_inputs);
            if let Some(inputs) = unsealed_inputs {
                let result = verify_bonded_deposit_core(&tx, &witness, &request.info, inputs);
                let txid = tx.id();
                let response: IntraEnclaveResponse = result.map(|_| {
                    IntraEnclaveResponseOk::Encrypt(encrypt(
                        TxToObfuscate::from(PlainTxAux::DepositStakeTx(witness), txid)
                            .expect("construct plain payload"),
                    ))
                });
                write_response(response, output);
            } else {
                log::debug!("failed to unseal inputs");
                write_response(Err(Error::EnclaveRejected), output);
            }
        }
        (Some(EncryptionRequest::WithdrawStake(tx, witness)), None) => {
            if let Some(account) = request.account {
                let txid = tx.id();
                let maddress = verify_tx_recover_address(&witness, &txid);
                match maddress {
                    Ok(address) if address == account.address => {
                        let result = verify_unbonded_withdraw_core(&tx, &request.info, &account);
                        let response: IntraEnclaveResponse = result.map(|_| {
                            IntraEnclaveResponseOk::Encrypt(encrypt(
                                TxToObfuscate::from(PlainTxAux::WithdrawUnbondedStakeTx(tx), txid)
                                    .expect("construct plain payload"),
                            ))
                        });
                        write_response(response, output);
                    }
                    _ => {
                        log::debug!("invalid address");
                        write_response(Err(Error::EnclaveRejected), output);
                    }
                }
            } else {
                log::debug!("no account");
                write_response(Err(Error::EnclaveRejected), output);
            }
        }
        (_, _) => {
            log::debug!("invalid request");
            write_response(Err(Error::EnclaveRejected), output);
        }
    }
}
