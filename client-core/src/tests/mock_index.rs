#![cfg(test)]

use std::path::Path;
use std::time::SystemTime;

use chrono::DateTime;

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::{Tx, TxId};
use client_common::balance::{BalanceChange, TransactionChange};
use client_common::Result;
use client_index::Index;

pub struct MockIndex;

impl MockIndex {
    pub fn new<P: AsRef<Path>>(_: P, _: &str) -> Self {
        Self
    }
}

impl Index for MockIndex {
    fn sync(&self) -> Result<()> {
        Ok(())
    }

    fn sync_all(&self) -> Result<()> {
        Ok(())
    }

    fn transaction_changes(&self, address: &ExtendedAddr) -> Result<Vec<TransactionChange>> {
        Ok(vec![TransactionChange {
            transaction_id: TxId::zero(),
            address: address.clone(),
            balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
            height: 1,
            time: DateTime::from(SystemTime::now()),
        }])
    }

    fn balance(&self, _: &ExtendedAddr) -> Result<Coin> {
        Ok(Coin::new(30).unwrap())
    }

    fn transaction(&self, _: &TxId) -> Result<Option<Tx>> {
        Ok(Some(Tx {
            inputs: Default::default(),
            outputs: Default::default(),
            attributes: TxAttributes::new(171),
        }))
    }
}
