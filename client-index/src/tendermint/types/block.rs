#![allow(missing_docs)]

use base64::decode;
use failure::ResultExt;
use serde::{Deserialize, Serialize};

use chain_core::tx::TxAux;
use client_common::{ErrorKind, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct Block {
    block: BlockInner,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockInner {
    data: Data,
}

#[derive(Debug, Serialize, Deserialize)]
struct Data {
    txs: Vec<String>,
}

impl Block {
    /// Returns transactions in a block (this may also contain invalid transactions)
    pub fn transactions(&self) -> Result<Vec<TxAux>> {
        self.block
            .data
            .txs
            .iter()
            .map(|raw_tx| Ok(decode(&raw_tx).context(ErrorKind::DeserializationError)?))
            .map(|bytes: Result<Vec<u8>>| {
                Ok(rlp::decode(&bytes?).context(ErrorKind::DeserializationError)?)
            })
            .collect::<Result<Vec<TxAux>>>()
    }
}

// Note: Do not change these values. These are tied with tests for `RpcSledIndex`
#[cfg(test)]
impl Default for Block {
    fn default() -> Self {
        Block {
            block: BlockInner {
                data: Data {
                    txs: vec!["+JWA+Erj4qBySKi4J+krjuZi++QuAnQITDv9YzjXV0RcDuk+S7pMeIDh4NaAlHkGYaL9naP+5TyquAhZ7K4SWiCliAAA6IkEI8eKw4GrwPhG+ESAAbhASZdu2rJI4Et7q93KedoEsTVFUOCPt8nyY0pGOqixhI4TvORYPVFmJiG+Lsr6L1wmwBLIwxJenWTyKZ8rKrwfkg==".to_owned()]
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_transactions() {
        let block = Block::default();
        assert_eq!(1, block.transactions().unwrap().len());
    }

    #[test]
    fn check_wrong_transaction() {
        let block = Block {
            block: BlockInner {
                data: Data {
                    txs: vec!["+JWA+Erj4qBySKi4J+krjuZi++QuAnQITDv9YzjXV0RcDuk+S7pMeIDh4NaA4SWiCliAAA6IkEI8eKw4GrwPhG+ESAAbhASZdu2rJI4Et7q93KedoEsTVFUOCPt8nyY0pGOqixhI4TvORYPVFmJiG+Lsr6L1wmwBLIwxJenWTyKZ8rKrwfkg==".to_owned()]
                }
            }
        };

        assert!(block.transactions().is_err());
    }
}
