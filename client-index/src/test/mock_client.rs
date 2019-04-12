#![cfg(test)]

use std::str::FromStr;

use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::init::config::{ERC20Owner, InitConfig};
use client_common::Result;

use crate::tendermint::types::*;
use crate::tendermint::Client;

#[derive(Clone)]
pub struct MockClient;

impl MockClient {
    pub fn new(_: &str) -> Self {
        Self
    }
}

impl Client for MockClient {
    fn genesis(&self) -> Result<Genesis> {
        Ok(Genesis {
            genesis: GenesisInner {
                chain_id: "test-chain-4UIy1Wab".to_owned(),
                app_state: InitConfig::new(vec![ERC20Owner::new(
                    RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
                    Coin::new(10000000000000000000).unwrap(),
                )]),
            },
        })
    }

    fn status(&self) -> Result<Status> {
        Ok(Status {
            sync_info: SyncInfo {
                latest_block_height: "1".to_owned(),
            },
        })
    }

    fn block(&self, _: u64) -> Result<Block> {
        Ok(Block {
            block: BlockInner {
                data: Data {
                    txs: vec!["+JWA+Erj4qBySKi4J+krjuZi++QuAnQITDv9YzjXV0RcDuk+S7pMeIDh4NaAlHkGYaL9naP+5TyquAhZ7K4SWiCliAAA6IkEI8eKw4GrwPhG+ESAAbhASZdu2rJI4Et7q93KedoEsTVFUOCPt8nyY0pGOqixhI4TvORYPVFmJiG+Lsr6L1wmwBLIwxJenWTyKZ8rKrwfkg==".to_owned()]
                }
            }
        })
    }

    fn block_results(&self, _: u64) -> Result<BlockResults> {
        Ok(BlockResults {
            height: "2".to_owned(),
            results: Results {
                deliver_tx: vec![DeliverTx {
                    tags: vec![Tag {
                        key: "dHhpZA==".to_owned(),
                        value: "kOzcmhZgAAaw5roBdqDNniwRjjKNe+foJEiDAOObTDQ=".to_owned(),
                    }],
                }],
            },
        })
    }
}
