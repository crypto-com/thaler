use std::sync::Arc;

use failure::Error;
use hex::decode;
use hex::encode;
use jsonrpc_derive::rpc;
use jsonrpc_http_server::jsonrpc_core;
use serde::{Deserialize, Serialize};
use serde_cbor::ser::to_vec_packed;
use zeroize::Zeroize;

use chain_core::common::Timespec;
use chain_core::init::coin::Coin;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::TxAux;
use signer_core::{
    get_transaction_witnesses, verify_redeem_address, verify_transaction_id, verify_tree_address,
    SecretsService, SignatureType,
};

use crate::command::to_rpc_error;

#[rpc]
pub trait TransactionRpc {
    #[rpc(name = "generateTransaction")]
    fn generate_transaction(
        &self,
        request: TransactionRequest,
    ) -> jsonrpc_core::Result<TransactionResponse>;
}

pub struct TransactionRpcImpl {
    service: Arc<SecretsService>,
}

impl TransactionRpcImpl {
    pub fn new(service: Arc<SecretsService>) -> TransactionRpcImpl {
        TransactionRpcImpl { service }
    }
}

impl TransactionRpc for TransactionRpcImpl {
    fn generate_transaction(
        &self,
        mut request: TransactionRequest,
    ) -> jsonrpc_core::Result<TransactionResponse> {
        let secrets = self
            .service
            .get(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;

        let transaction = request.transaction.into_tx().map_err(to_rpc_error)?;

        let witnesses = get_transaction_witnesses(&transaction, &secrets, &request.signature_types)
            .map_err(to_rpc_error)?;

        request.passphrase.zeroize();

        let txa = TxAux::new(transaction, witnesses);

        let response = TransactionResponse {
            transaction_id: encode(&txa.tx.id()).to_string(),
            transaction: encode(&to_vec_packed(&txa).map_err(|e| to_rpc_error(e.into()))?)
                .to_string(),
        };

        Ok(response)
    }
}

#[derive(Debug, Deserialize)]
pub struct TransactionRequest {
    name: String,
    passphrase: String,
    transaction: Transaction,
    signature_types: Vec<SignatureType>,
}

#[derive(Debug, Serialize)]
pub struct TransactionResponse {
    transaction_id: String,
    transaction: String,
}

#[derive(Debug, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub chain_id: String,
}

#[derive(Debug, Deserialize)]
pub struct TransactionInput {
    pub id: String,
    pub index: usize,
}

#[derive(Debug, Deserialize)]
pub struct TransactionOutput {
    pub address: String,
    pub address_type: AddressType,
    pub value: Coin,
    pub valid_from: Option<Timespec>,
}

#[derive(Debug, Deserialize)]
pub enum AddressType {
    #[serde(alias = "redeem")]
    Redeem,
    #[serde(alias = "tree")]
    Tree,
}

impl Transaction {
    pub fn into_tx(self) -> Result<Tx, Error> {
        let mut transaction = Tx::new();
        transaction.attributes = TxAttributes::new(decode(self.chain_id)?[0]);

        self.inputs
            .into_iter()
            .map(TransactionInput::into_txo_pointer)
            .collect::<Result<Vec<_>, Error>>()?
            .into_iter()
            .for_each(|pointer| transaction.add_input(pointer));

        self.outputs
            .into_iter()
            .map(TransactionOutput::into_tx_out)
            .collect::<Result<Vec<_>, Error>>()?
            .into_iter()
            .for_each(|out| transaction.add_output(out));

        Ok(transaction)
    }
}

impl TransactionInput {
    pub fn into_txo_pointer(self) -> Result<TxoPointer, Error> {
        let transaction_id = verify_transaction_id(self.id)?;
        Ok(TxoPointer::new(transaction_id, self.index))
    }
}

impl TransactionOutput {
    pub fn into_tx_out(self) -> Result<TxOut, Error> {
        let address = match self.address_type {
            AddressType::Redeem => verify_redeem_address(self.address)?,
            AddressType::Tree => verify_tree_address(self.address)?,
        };

        match self.valid_from {
            None => Ok(TxOut::new(address, self.value)),
            Some(timespec) => Ok(TxOut::new_with_timelock(address, self.value, timespec)),
        }
    }
}
