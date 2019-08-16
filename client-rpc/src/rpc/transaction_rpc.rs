use failure::ResultExt;
use hex::{decode, encode};
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize};
use secstr::SecUtf8;

use chain_core::tx::TransactionId;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::{TxoPointer, TxoIndex};
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::data::output::TxOut;
use chain_core::common::{H256, HASH_SIZE_256};
use client_common::{Error, ErrorKind, PublicKey, Result as CommonResult};

use crate::server::{to_rpc_error, WalletRequest};

#[derive(Serialize, Deserialize)]
pub struct RawTransaction {
    tx: Tx,
    tx_id: TxId,
}

#[rpc]
pub trait TransactionRpc: Send + Sync {
    #[rpc(name = "transaction_createRaw")]
    fn create_raw(
        &self,
        inputs: Vec<TxoPointer>,
        outputs: Vec<TxOut>,
        view_keys: Vec<String>,
    ) -> Result<RawTransaction>;
}

pub struct TransactionRpcImpl { }

impl TransactionRpcImpl {
    pub fn new() -> Self {
        TransactionRpcImpl { }
    }
}

impl TransactionRpc for TransactionRpcImpl {
    fn create_raw(
        &self,
        inputs: Vec<TxoPointer>,
        outputs: Vec<TxOut>,
        view_keys: Vec<String>,
    ) -> Result<RawTransaction> {
        let tx = Tx {
            inputs,
            outputs,
            attributes,
        } 

        RawTransaction {
            tx,
            tx.id(),
        }
    }
}
