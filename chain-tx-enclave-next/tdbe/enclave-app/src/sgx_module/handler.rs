use std::net::TcpStream;

use parity_scale_codec::{Decode, Encode};
use zeroize::Zeroize;

use chain_core::tx::{data::TxId, TxWithOutputs};
use enclave_protocol::{
    codec::{StreamRead, StreamWrite},
    EnclaveRequest, EnclaveResponse,
};
use enclave_utils::SealedData;

/// Retrieves all the transactions with outputs with given transaction IDs
pub fn get_transactions_with_outputs(
    transaction_ids: Vec<TxId>,
    chain_abci: &mut TcpStream,
) -> Result<Vec<TxWithOutputs>, String> {
    // Prepare enclave request
    let enclave_request = EnclaveRequest::GetSealedTxData {
        txids: transaction_ids.clone(),
    }
    .encode();

    // Send request to chain-abci
    enclave_request
        .write_to(&*chain_abci)
        .map_err(|err| format!("Unable to send request to chain-abci: {}", err))?;

    // Read response from chain-abci
    let enclave_response = EnclaveResponse::read_from(&*chain_abci)
        .map_err(|err| format!("Unable to receive response from chain-abci: {}", err))?;

    match enclave_response {
        EnclaveResponse::GetSealedTxData(Some(sealed_logs)) => {
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
        EnclaveResponse::GetSealedTxData(None) => Err("Transactions not found".to_owned()),
        _ => Err("Unexpected response from ZeroMQ".to_owned()),
    }
}
