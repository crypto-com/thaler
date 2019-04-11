#![cfg(test)]

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
        Ok(Default::default())
    }

    fn status(&self) -> Result<Status> {
        Ok(Default::default())
    }

    fn block(&self, _: u64) -> Result<Block> {
        Ok(Default::default())
    }

    fn block_results(&self, _: u64) -> Result<BlockResults> {
        Ok(Default::default())
    }
}
