use parity_scale_codec::{Decode, Encode};

use chain_core::state::tendermint::BlockHeight;
use chain_core::tx::{data::TxId, PlainTxAux, TxObfuscated, TxWithOutputs};
use chain_tx_validation::Error;

const ENCRYPTION_KEY: u8 = 0x0f;
const SEAL_KEY: u8 = 0xf0;
pub fn decrypt(payload: &TxObfuscated) -> Result<PlainTxAux, Error> {
    let unpad = unpad_payload(&payload.txpayload);
    let bs = unpad.iter().map(|b| b ^ ENCRYPTION_KEY).collect::<Vec<_>>();
    PlainTxAux::decode(&mut bs.as_slice()).map_err(|_| Error::EnclaveRejected)
}

fn unpad_payload(payload: &[u8]) -> &[u8] {
    &payload[0..payload.len() - 16]
}

pub fn seal(tx: &TxWithOutputs) -> Vec<u8> {
    tx.encode()
        .into_iter()
        .map(|b| b ^ SEAL_KEY)
        .collect::<Vec<_>>()
}
pub fn unseal(payload: &[u8]) -> Result<TxWithOutputs, Error> {
    let bytes = payload.iter().map(|b| b ^ SEAL_KEY).collect::<Vec<_>>();
    TxWithOutputs::decode(&mut bytes.as_slice()).map_err(|_| Error::EnclaveRejected)
}
fn pad_payload(payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(payload.len() + 16);
    result.extend_from_slice(payload);
    result.extend_from_slice(&[0; 16]);
    result
}
pub fn encrypt_payload(plain: &PlainTxAux) -> Vec<u8> {
    pad_payload(
        &plain
            .encode()
            .into_iter()
            .map(|b| b ^ ENCRYPTION_KEY)
            .collect::<Vec<_>>(),
    )
}
pub fn encrypt(plain: &PlainTxAux, txid: TxId) -> TxObfuscated {
    TxObfuscated {
        key_from: BlockHeight::genesis(),
        init_vector: [0; 12],
        txpayload: encrypt_payload(plain),
        txid,
    }
}
