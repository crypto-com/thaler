mod constants;
mod secrets;
mod secrets_service;
mod storage;

pub use secrets::{AddressType, Secrets};
pub use secrets_service::SecretsService;
pub use storage::Storage;

use failure::{format_err, Error};
use hex::decode;
use secp256k1::Message;
use serde::{Deserialize, Serialize};

use chain_core::common::HASH_SIZE_256;
use chain_core::init::address::REDEEM_ADDRESS_BYTES;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::witness::{TxInWitness, TxWitness};

/// Enum specifying different signature types
#[derive(Debug, Serialize, Deserialize)]
pub enum SignatureType {
    #[serde(alias = "ecdsa")]
    ECDSA,
    #[serde(alias = "schnorr")]
    Schnorr,
}

/// Returns transaction witnesses after signing
pub fn get_transaction_witnesses(
    transaction: &Tx,
    secrets: &Secrets,
    required_signature_types: &[SignatureType],
) -> Result<TxWitness, Error> {
    let message = Message::from_slice(&transaction.id().as_bytes())?;

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

/// Verifies the transaction id
pub fn verify_transaction_id(transaction_id: String) -> Result<TxId, Error> {
    let transaction_id = decode(&transaction_id)?;

    if HASH_SIZE_256 != transaction_id.len() {
        Err(format_err!("Invalid transaction id"))
    } else {
        let mut new_transaction_id = [0; HASH_SIZE_256];
        new_transaction_id.copy_from_slice(&transaction_id);
        Ok(new_transaction_id.into())
    }
}

/// Verifies redeem address
pub fn verify_redeem_address(address: String) -> Result<ExtendedAddr, Error> {
    let address = decode(&address)?;

    if REDEEM_ADDRESS_BYTES != address.len() {
        Err(format_err!("Invalid redeem address"))
    } else {
        let mut addr = [0; REDEEM_ADDRESS_BYTES];
        addr.copy_from_slice(&address);
        Ok(ExtendedAddr::BasicRedeem(addr.into()))
    }
}

/// Verifies tree address
pub fn verify_tree_address(address: String) -> Result<ExtendedAddr, Error> {
    let address = decode(&address)?;

    if HASH_SIZE_256 != address.len() {
        Err(format_err!("Invalid tree address"))
    } else {
        let mut addr = [0; HASH_SIZE_256];
        addr.copy_from_slice(&address);
        Ok(ExtendedAddr::OrTree(addr.into()))
    }
}
