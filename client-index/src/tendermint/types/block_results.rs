#![allow(missing_docs)]

use base64::decode;
use failure::ResultExt;
use serde::{Deserialize, Serialize};

use chain_core::tx::data::TxId;
use client_common::{ErrorKind, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockResults {
    height: String,
    results: Results,
}

#[derive(Debug, Serialize, Deserialize)]
struct Results {
    #[serde(rename = "DeliverTx")]
    pub deliver_tx: Vec<DeliverTx>,
    #[serde(rename = "BeginBlock")]
    pub begin_block: BeginBlock,
}

#[derive(Debug, Serialize, Deserialize)]
struct BeginBlock {}

#[derive(Debug, Serialize, Deserialize)]
struct DeliverTx {
    pub tags: Vec<Tag>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Tag {
    pub key: String,
    pub value: String,
}

impl BlockResults {
    /// Returns valid transaction ids in block results
    pub fn ids(&self) -> Result<Vec<TxId>> {
        let mut transactions: Vec<TxId> = Default::default();

        for transaction in self.results.deliver_tx.iter() {
            for tag in transaction.tags.iter() {
                let decoded = decode(&tag.value).context(ErrorKind::DeserializationError)?;
                if 32 != decoded.len() {
                    return Err(ErrorKind::DeserializationError.into());
                }

                let mut id: [u8; 32] = [0; 32];
                id.copy_from_slice(&decoded);

                transactions.push(id.into());
            }
        }

        Ok(transactions)
    }
}
