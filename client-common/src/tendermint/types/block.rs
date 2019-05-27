#![allow(missing_docs)]

use base64::decode;
use chain_core::tx::TxAux;
use chrono::offset::Utc;
use chrono::DateTime;
use failure::ResultExt;
use parity_codec::Decode;
use serde::Deserialize;

use crate::{ErrorKind, Result};

#[derive(Debug, Deserialize)]
pub struct Block {
    pub block: BlockInner,
}

#[derive(Debug, Deserialize)]
pub struct BlockInner {
    pub header: Header,
    pub data: Data,
}

#[derive(Debug, Deserialize)]
pub struct Data {
    pub txs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct Header {
    pub height: String,
    pub time: DateTime<Utc>,
}

impl Block {
    /// Returns transactions in a block (this may also contain invalid transactions)
    pub fn transactions(&self) -> Result<Vec<TxAux>> {
        match &self.block.data.txs {
            None => Ok(Vec::new()),
            Some(txs) => txs
                .iter()
                .map(|raw_tx| Ok(decode(&raw_tx).context(ErrorKind::DeserializationError)?))
                .map(|bytes: Result<Vec<u8>>| {
                    Ok(TxAux::decode(&mut bytes?.as_slice())
                        .ok_or(ErrorKind::DeserializationError)?)
                })
                .collect::<Result<Vec<TxAux>>>(),
        }
    }

    /// Returns height of this block
    pub fn height(&self) -> Result<u64> {
        Ok(self
            .block
            .header
            .height
            .parse::<u64>()
            .context(ErrorKind::DeserializationError)?)
    }

    /// Returns time of this block
    pub fn time(&self) -> DateTime<Utc> {
        self.block.header.time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn check_transactions() {
        let block = Block {
            block: BlockInner {
                header: Header {
                    height: "1".to_owned(),
                    time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                },
                data: Data {
                    txs: Some(vec!["AAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAAAAAAgAqqqqqqqqqqqqqqqqqqqqqqqqqqoBAAAAAAAAAAABu7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7sBAAAAAAAAAAAAAgAIAAICuVwknYT0F+PjlaEnQlQotUBnHMFYgeuCjBe3IqU/xZkAAAIC7YNwTJXYKQRvGsJ4BiERMhAsNOmsf/obcREGWOW50b0BAAAAAAAAAAAIAAIAoV8+HKEaYx7BTan0dqjf4wRgQsF20TOzcyIWS5DGOlhZgYCYHGGJeKQFoW/SFQ9ro0T6wCUQGKx5bwI1fQLuNgED+Qqa2DMw1XO5CdN5z9iYlTXavEIr2yo8Nju1LTXR3o9DR7y1V+3BaXTX0CPbtXutT7nd3K38covYnDoywrXyGziJDKviK2SN9APgEMXplV5PJ+flLB6Q7xSi13J2LULTOIkMq+IrZI30A+AQxemVXk8n5+UsHpDvFKLXcnYtQtMAAeobU4Pb5MTS8GpaOGA72O5kuur5WsUHeZRtzLXVwE3LAQEYpa15lwA+8sw4e7cvN/jvyJRS4jqp4XRiQ8yjAQFzbQACuVwknYT0F+PjlaEnQlQotUBnHMFYgeuCjBe3IqU/xZk=".to_owned()])
                }
            }
        };
        assert_eq!(1, block.transactions().unwrap().len());
    }

    #[test]
    fn check_wrong_transaction() {
        let block = Block {
            block: BlockInner {
                header: Header {
                    height: "1".to_owned(),
                    time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                },
                data: Data {
                    txs: Some(vec!["+JWA+Erj4qBySKi4J+krjuZi++QuAnQITDv9YzjXV0RcDuk+S7pMeIDh4NaA4SWiCliAAA6IkEI8eKw4GrwPhG+ESAAbhASZdu2rJI4Et7q93KedoEsTVFUOCPt8nyY0pGOqixhI4TvORYPVFmJiG+Lsr6L1wmwBLIwxJenWTyKZ8rKrwfkg==".to_owned()])
                }
            }
        };

        assert!(block.transactions().is_err());
    }

    #[test]
    fn check_height() {
        let block = Block {
            block: BlockInner {
                header: Header {
                    height: "1".to_owned(),
                    time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                },
                data: Data {
                    txs: Some(vec!["+JWA+Erj4qBySKi4J+krjuZi++QuAnQITDv9YzjXV0RcDuk+S7pMeIDh4NaAlHkGYaL9naP+5TyquAhZ7K4SWiCliAAA6IkEI8eKw4GrwPhG+ESAAbhASZdu2rJI4Et7q93KedoEsTVFUOCPt8nyY0pGOqixhI4TvORYPVFmJiG+Lsr6L1wmwBLIwxJenWTyKZ8rKrwfkg==".to_owned()])
                }
            }
        };

        assert_eq!(1, block.height().unwrap());
    }

    #[test]
    fn check_wrong_height() {
        let block = Block {
            block: BlockInner {
                header: Header {
                    height: "a".to_owned(),
                    time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                },
                data: Data {
                    txs: Some(vec!["+JWA+Erj4qBySKi4J+krjuZi++QuAnQITDv9YzjXV0RcDuk+S7pMeIDh4NaAlHkGYaL9naP+5TyquAhZ7K4SWiCliAAA6IkEI8eKw4GrwPhG+ESAAbhASZdu2rJI4Et7q93KedoEsTVFUOCPt8nyY0pGOqixhI4TvORYPVFmJiG+Lsr6L1wmwBLIwxJenWTyKZ8rKrwfkg==".to_owned()])
                }
            }
        };

        assert!(block.height().is_err());
    }

    #[test]
    fn check_null_transactions() {
        let block = Block {
            block: BlockInner {
                header: Header {
                    height: "1".to_owned(),
                    time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                },
                data: Data { txs: None },
            },
        };
        assert_eq!(0, block.transactions().unwrap().len());
    }
}
