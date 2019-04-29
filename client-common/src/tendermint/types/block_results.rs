#![allow(missing_docs)]
use std::collections::HashSet;

use base64::decode;
use failure::ResultExt;
use serde::Deserialize;

use crate::{ErrorKind, Result};
use chain_core::tx::data::TxId;

#[derive(Debug, Deserialize)]
pub struct BlockResults {
    pub height: String,
    pub results: Results,
}

#[derive(Debug, Deserialize)]
pub struct Results {
    #[serde(rename = "DeliverTx")]
    pub deliver_tx: Option<Vec<DeliverTx>>,
}

#[derive(Debug, Deserialize)]
pub struct DeliverTx {
    pub tags: Vec<Tag>,
}

#[derive(Debug, Deserialize)]
pub struct Tag {
    pub key: String,
    pub value: String,
}

impl BlockResults {
    /// Returns valid transaction ids in block results
    pub fn ids(&self) -> Result<HashSet<TxId>> {
        match &self.results.deliver_tx {
            None => Ok(HashSet::new()),
            Some(deliver_tx) => {
                let mut transactions: HashSet<TxId> = HashSet::with_capacity(deliver_tx.len());

                for transaction in deliver_tx.iter() {
                    for tag in transaction.tags.iter() {
                        let decoded =
                            decode(&tag.value).context(ErrorKind::DeserializationError)?;
                        if 32 != decoded.len() {
                            return Err(ErrorKind::DeserializationError.into());
                        }

                        let mut id: [u8; 32] = [0; 32];
                        id.copy_from_slice(&decoded);

                        transactions.insert(id.into());
                    }
                }

                Ok(transactions)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_ids() {
        let block_results = BlockResults {
            height: "2".to_owned(),
            results: Results {
                deliver_tx: Some(vec![DeliverTx {
                    tags: vec![Tag {
                        key: "dHhpZA==".to_owned(),
                        value: "kOzcmhZgAAaw5roBdqDNniwRjjKNe+foJEiDAOObTDQ=".to_owned(),
                    }],
                }]),
            },
        };
        assert_eq!(1, block_results.ids().unwrap().len());
    }

    #[test]
    fn check_wrong_id() {
        let block_results = BlockResults {
            height: "2".to_owned(),
            results: Results {
                deliver_tx: Some(vec![DeliverTx {
                    tags: vec![Tag {
                        key: "dHhpZA==".to_owned(),
                        value: "kOzcmhZgAAaw5riwRjjKNe+foJEiDAOObTDQ=".to_owned(),
                    }],
                }]),
            },
        };

        assert!(block_results.ids().is_err());
    }

    #[test]
    fn check_null_deliver_tx() {
        let block_results = BlockResults {
            height: "2".to_owned(),
            results: Results { deliver_tx: None },
        };
        assert_eq!(0, block_results.ids().unwrap().len());
    }
}
