#![cfg(test)]

use client_common::balance::TransactionChange;
use client_common::{Chain, Result};

/// A mock chain client
#[derive(Clone, Default)]
pub struct MockChain;

impl Chain for MockChain {
    fn query_transaction_changes(
        &self,
        _addresses: Vec<String>,
        _last_block_height: u64,
    ) -> Result<(Vec<TransactionChange>, u64)> {
        Ok((Default::default(), Default::default()))
    }
}
