#![allow(missing_docs)]
use std::convert::TryFrom;

use base64;
use serde::Deserialize;

use chain_core::common::TendermintEventType;
use chain_core::tx::data::TxId;
use chain_tx_filter::BlockFilter;

use crate::{Error, ErrorKind, Result, ResultExt};

#[derive(Debug, Deserialize)]
pub struct BlockResults {
    pub height: String,
    pub results: Results,
}

#[derive(Debug, Deserialize)]
pub struct Results {
    pub deliver_tx: Option<Vec<DeliverTx>>,
    pub end_block: Option<EndBlock>,
}

#[derive(Debug, Deserialize)]
pub struct EndBlock {
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
pub struct DeliverTx {
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub event_type: String,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Deserialize)]
pub struct Attribute {
    pub key: String,
    pub value: String,
}

impl BlockResults {
    /// Returns transaction ids in block results
    pub fn transaction_ids(&self) -> Result<Vec<TxId>> {
        match &self.results.deliver_tx {
            None => Ok(Vec::default()),
            Some(deliver_tx) => {
                let mut transactions: Vec<TxId> = Vec::with_capacity(deliver_tx.len());

                for transaction in deliver_tx.iter() {
                    for event in transaction.events.iter() {
                        if event.event_type == TendermintEventType::ValidTransactions.to_string() {
                            let tx_id = find_tx_id_from_event_attributes(&event.attributes)?;
                            match tx_id {
                                Some(tx_id) => {
                                    transactions.push(tx_id);
                                }
                                None => (),
                            };
                        }
                    }
                }

                Ok(transactions)
            }
        }
    }

    /// Returns block filter in block results
    pub fn block_filter(&self) -> Result<BlockFilter> {
        match &self.results.end_block {
            None => Ok(BlockFilter::default()),
            Some(ref end_block) => {
                for event in end_block.events.iter() {
                    if event.event_type == TendermintEventType::BlockFilter.to_string() {
                        let attribute = &event.attributes[0];
                        let decoded = base64::decode(&attribute.value).chain(|| {
                            (
                                ErrorKind::DeserializationError,
                                "Unable to decode base64 bytes of block filter in block results",
                            )
                        })?;

                        return Ok(BlockFilter::try_from(decoded.as_slice()).map_err(
                            |message| Error::new(ErrorKind::DeserializationError, message),
                        )?);
                    }
                }

                Ok(BlockFilter::default())
            }
        }
    }
}

fn find_tx_id_from_event_attributes(attributes: &Vec<Attribute>) -> Result<Option<[u8; 32]>> {
    for attribute in attributes.iter() {
        let key = base64::decode(&attribute.key).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to decode base64 bytes of attribute key in block results",
            )
        })?;
        if key != b"tx.id" {
            continue;
        }

        let tx_id = base64::decode(&attribute.value).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to decode base64 bytes of transaction id in block results",
            )
        })?;
        let tx_id = hex::decode(&tx_id).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to decode hex bytes of transaction id in block results",
            )
        })?;
        if 32 != tx_id.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Expected transaction id of 32 bytes",
            ));
        }
        let mut id: [u8; 32] = [0; 32];
        id.copy_from_slice(&tx_id);

        return Ok(Some(id));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::encode;

    #[test]
    fn check_ids() {
        let block_results = BlockResults {
            height: "2".to_owned(),
            results: Results {
                deliver_tx: Some(vec![DeliverTx {
                    events: vec![Event {
                        event_type: TendermintEventType::ValidTransactions.to_string(),
                        attributes: vec![Attribute {
                            key: "dHguaWQ=".to_owned(),
                            value: "MDc2NmQ0ZTFjMDkxMjRhZjlhZWI0YTdlZDk5ZDgxNjU0YTg0NDczZjEzMzk0OGNlYTA1MGRhYTE3ZmYwZTdmZg==".to_owned(),
                        }],
                    }],
                }]),
                end_block: None,
            },
        };
        assert_eq!(1, block_results.transaction_ids().unwrap().len());
    }

    #[test]
    fn check_block_filter() {
        let block_results = BlockResults {
            height: "2".to_owned(),
            results: Results {
                deliver_tx: None,
                end_block: Some(EndBlock {
                    events: vec![Event {
                        event_type: TendermintEventType::BlockFilter.to_string(),
                        attributes: vec![Attribute {
                            key: "ethbloom".to_owned(),
                            value: encode(&[0; 256][..]),
                        }],
                    }],
                }),
            },
        };
        assert!(block_results.block_filter().is_ok());
    }

    #[test]
    fn check_wrong_id() {
        let block_results = BlockResults {
            height: "2".to_owned(),
            results: Results {
                deliver_tx: Some(vec![DeliverTx {
                    events: vec![Event {
                        event_type: TendermintEventType::ValidTransactions.to_string(),
                        attributes: vec![Attribute {
                            key: "dHguaWQ=".to_owned(),
                            value: "kOzcmhZgAAaw5riwRjjKNe+foJEiDAOObTDQ=".to_owned(),
                        }],
                    }],
                }]),
                end_block: None,
            },
        };

        assert!(block_results.transaction_ids().is_err());
    }

    #[test]
    fn check_null_deliver_tx() {
        let block_results = BlockResults {
            height: "2".to_owned(),
            results: Results {
                deliver_tx: None,
                end_block: None,
            },
        };
        assert_eq!(0, block_results.transaction_ids().unwrap().len());
    }
}
