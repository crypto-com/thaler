use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use chain_core::tx::TransactionId;
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::data::output::TxOut;
use client_common::{PublicKey, Result as CommonResult};

use crate::server::{to_rpc_error};

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

pub struct TransactionRpcImpl {
    network_id: u8,
}

impl TransactionRpcImpl {
    pub fn new(network_id: u8) -> Self {
        TransactionRpcImpl { network_id }
    }
}

impl TransactionRpc for TransactionRpcImpl {
    fn create_raw(
        &self,
        inputs: Vec<TxoPointer>,
        outputs: Vec<TxOut>,
        view_keys: Vec<String>,
    ) -> Result<RawTransaction> {
        let view_keys = view_keys
            .iter()
            .map(|view_key| PublicKey::from_str(view_key))
            .collect::<CommonResult<Vec<PublicKey>>>()
            .map_err(to_rpc_error)?;

        let mut access_policies: Vec<TxAccessPolicy> = vec![];

        for key in view_keys.iter() {
            access_policies.push(TxAccessPolicy {
                view_key: key.into(),
                access: TxAccess::AllData,
            });
        }

        let attributes = TxAttributes::new_with_access(self.network_id, access_policies);

        let tx = Tx {
            inputs,
            outputs,
            attributes,
        };
        let tx_id = tx.id();

        Ok(RawTransaction {
            tx,
            tx_id,
        })
    }
}
