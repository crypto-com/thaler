mod secrets;
mod storage;
mod constants;
mod secrets_service;

pub use secrets::{AddressType, Secrets};
pub use storage::Storage;
pub use secrets_service::SecretsService;

use failure::Error;
use secp256k1::Message;

use chain_core::tx::data::Tx;
use chain_core::tx::witness::{TxInWitness, TxWitness};

/// Enum specifying different signature types
#[derive(Debug)]
pub enum SignatureType {
    ECDSA,
    Schnorr,
}

/// Returns transaction witnesses after signing
pub fn get_transaction_witnesses(
    transaction: &Tx,
    secrets: &Secrets,
    required_signature_types: &[SignatureType],
) -> Result<TxWitness, Error> {
    let message = Message::from_slice(&transaction.id())?;

    let ecdsa_signature = secrets.get_ecdsa_signature(&message)?;
    let schnorr_signature = secrets.get_schnorr_signature(&message)?;

    let witnesses: Vec<TxInWitness> = required_signature_types
        .iter()
        .map(|x| match x {
            SignatureType::ECDSA => ecdsa_signature.clone(),
            SignatureType::Schnorr => schnorr_signature.clone(),
        })
        .collect();

    Ok(witnesses.into())
}
