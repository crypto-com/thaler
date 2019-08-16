use failure::ResultExt;
use hex::{decode, encode};
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use secstr::SecUtf8;

use chain_core::tx::TransactionId;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::{TxoPointer, TxoIndex};
use chain_core::tx::data::Tx;
use chain_core::tx::data::output::TxOut;
use chain_core::common::{H256, HASH_SIZE_256};
use client_common::{Error, ErrorKind, PublicKey, Result as CommonResult};

use crate::server::{to_rpc_error, WalletRequest};

#[rpc]
pub trait TransactionRpc: Send + Sync {
    #[rpc(name = "transaction_createRaw")]
    fn create_raw(
        &self,
        inputs: Vec<TxoPointer>,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
    ) -> Result<String>;
}

pub struct TransactionRpcImpl { }

impl TransactionRpcImpl {
    pub fn new() -> Self {
        TransactionRpcImpl { }
    }
}

impl TransactionRpc for TransactionRpcImpl {
}

fn build_raw_transaction(
    inputs: Vec<TxoPointer>,
    outputs: Vec<TxOut>,
    attributes: TxAttributes,
) -> (Tx, TxId) {
    let tx = Tx {
        inputs,
        outputs,
        attributes,
    } 

    (tx, tx.id())
}