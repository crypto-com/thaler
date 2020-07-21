use std::{
    convert::TryInto,
    io::{Read, Write},
    net::TcpStream,
};

use parity_scale_codec::{Decode, Encode};
use zeroize::Zeroize;

use chain_core::tx::{data::TxId, TxWithOutputs};
use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use enclave_utils::SealedData;

/// Retrieves all the transactions with outputs with given transaction IDs
pub fn get_transactions_with_outputs(
    transaction_ids: Vec<TxId>,
    zmq_stream: &mut TcpStream,
) -> Result<Vec<TxWithOutputs>, String> {
    // Prepare enclave request
    let enclave_request = EnclaveRequest::GetSealedTxData {
        txids: transaction_ids.clone(),
    }
    .encode();

    // Send request to ZeroMQ
    zmq_stream
        .write_all(&enclave_request)
        .map_err(|err| format!("Error while writing request to ZeroMQ: {}", err))?;

    // Read reponse length from ZeroMQ (little endian u32 bytes)
    let mut response_len = [0u8; 4];
    zmq_stream
        .read(&mut response_len)
        .map_err(|err| format!("Error while reading reponse length from ZeroMQ: {}", err))?;

    let response_len: usize = u32::from_le_bytes(response_len)
        .try_into()
        .expect("Response length exceeds `usize` bounds");

    // Read result from ZeroMQ
    let mut result_buf = vec![0u8; response_len];
    zmq_stream
        .read(&mut result_buf)
        .map_err(|err| format!("Error while reading response from ZeroMQ: {}", err))?;

    match EnclaveResponse::decode(&mut result_buf.as_ref()) {
        Ok(EnclaveResponse::GetSealedTxData(Some(sealed_logs))) => {
            let mut transactions_with_outputs = Vec::with_capacity(sealed_logs.len());

            for (txid, sealed_log) in transaction_ids.into_iter().zip(sealed_logs.into_iter()) {
                let sealed_data = match SealedData::try_copy_from(&sealed_log) {
                    Some(sealed_data) => sealed_data,
                    None => {
                        return Err("Unable to parse sealed data returned from ZeroMQ".to_owned())
                    }
                };

                if sealed_data.aes_data.additional_txt != txid {
                    return Err("Transaction ID does not match in sealed data".to_owned());
                }

                let mut unsealed_data = sealed_data
                    .unseal()
                    .map_err(|e| format!("Error while unsealing sealed data: {:?}", e))?;
                let transaction_with_outputs = TxWithOutputs::decode(&mut unsealed_data.as_slice())
                    .map_err(|e| format!("Unable to decode unsealed data: {}", e))?;

                transactions_with_outputs.push(transaction_with_outputs);
                unsealed_data.zeroize();
            }

            Ok(transactions_with_outputs)
        }
        Ok(EnclaveResponse::GetSealedTxData(None)) => Err("Transactions not found".to_owned()),
        Ok(_) => Err("Unexpected response from ZeroMQ".to_owned()),
        Err(err) => Err(format!(
            "Error while decoding response from ZeroMQ: {}",
            err
        )),
    }
}
