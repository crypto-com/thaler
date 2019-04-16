#![cfg(all(feature = "sled", feature = "rpc"))]

use std::path::Path;

use chrono::offset::Utc;
use chrono::DateTime;

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::TxAux;
use client_common::balance::{BalanceChange, TransactionChange};
use client_common::storage::SledStorage;
use client_common::{ErrorKind, Result};

use crate::service::*;
use crate::tendermint::Client;
#[cfg(not(test))]
use crate::tendermint::RpcClient;
#[cfg(test)]
use crate::tests::MockClient;
use crate::Index;

/// Transaction index backed by `sled` embedded database and `RpcClient`
pub struct RpcSledIndex {
    address_service: AddressService<SledStorage>,
    balance_service: BalanceService<SledStorage>,
    global_state_service: GlobalStateService<SledStorage>,
    transaction_outputs_service: TransactionOutputsService<SledStorage>,
    transaction_service: TransactionService<SledStorage>,
    #[cfg(not(test))]
    client: RpcClient,
    #[cfg(test)]
    client: MockClient,
}

impl RpcSledIndex {
    /// Creates a new instance of `RpcSledIndex`
    pub fn new<P: AsRef<Path>>(path: P, url: &str) -> Result<Self> {
        #[cfg(not(test))]
        let storage = SledStorage::new(path)?;
        #[cfg(test)]
        let storage = SledStorage::temp(path)?;

        #[cfg(not(test))]
        let client = RpcClient::new(url);
        #[cfg(test)]
        let client = MockClient::new(url);

        Ok(Self {
            address_service: AddressService::new(storage.clone()),
            balance_service: BalanceService::new(storage.clone()),
            global_state_service: GlobalStateService::new(storage.clone()),
            transaction_outputs_service: TransactionOutputsService::new(storage.clone()),
            transaction_service: TransactionService::new(storage),
            client,
        })
    }

    /// Clears all the services
    fn clear(&self) -> Result<()> {
        self.address_service.clear()?;
        self.balance_service.clear()?;
        self.global_state_service.clear()?;
        self.transaction_outputs_service.clear()?;
        self.transaction_service.clear()
    }

    /// Handles genesis transactions
    fn genesis(&self) -> Result<()> {
        let genesis = self.client.genesis()?;
        let genesis_transactions = genesis.transactions()?;
        self.handle_transactions(&genesis_transactions, 0, genesis.time())?;

        Ok(())
    }

    /// Handles transactions by calling appropriate functions of different services
    fn handle_transactions(
        &self,
        transactions: &[Tx],
        height: u64,
        time: DateTime<Utc>,
    ) -> Result<()> {
        let changes = self.changes(transactions, height, time)?;

        for change in changes {
            self.balance_service
                .change(&change.address, &change.balance_change)?;

            self.address_service.add(change)?;
        }

        for transaction in transactions {
            let id = transaction.id();

            self.transaction_outputs_service
                .set(&id, &transaction.outputs)?;
            self.transaction_service.set(&id, transaction)?;
        }

        self.global_state_service.set_last_block_height(height)?;

        Ok(())
    }

    /// Converts `[Tx] -> [TransactionChange]`
    fn changes(
        &self,
        transactions: &[Tx],
        height: u64,
        time: DateTime<Utc>,
    ) -> Result<Vec<TransactionChange>> {
        let mut changes = Vec::new();

        for transaction in transactions {
            let id = transaction.id();

            for input in transaction.inputs.iter() {
                let index = input.index;
                let input = self
                    .transaction_outputs_service
                    .get(&input.id)?
                    .into_iter()
                    .nth(index);

                match input {
                    None => return Err(ErrorKind::InvalidTransaction.into()),
                    Some(input) => {
                        changes.push(TransactionChange {
                            transaction_id: id,
                            address: input.address,
                            balance_change: BalanceChange::Outgoing(input.value),
                            height,
                            time,
                        });
                    }
                }
            }

            for output in transaction.outputs.iter() {
                changes.push(TransactionChange {
                    transaction_id: id,
                    address: output.address.clone(),
                    balance_change: BalanceChange::Incoming(output.value),
                    height,
                    time,
                });
            }
        }

        Ok(changes)
    }
}

impl Index for RpcSledIndex {
    fn sync(&self) -> Result<()> {
        let last_block_height = match self.global_state_service.last_block_height()? {
            None => {
                self.genesis()?;
                0
            }
            Some(last_block_height) => last_block_height,
        };

        let current_block_height = self.client.status()?.last_block_height()?;

        for height in (last_block_height + 1)..=current_block_height {
            let valid_ids = self.client.block_results(height)?.ids()?;
            let block = self.client.block(height)?;
            let transactions = block
                .transactions()?
                .into_iter()
                .map(|tx_aux| match tx_aux {
                    TxAux::TransferTx(tx, _) => tx,
                })
                .filter(|tx| valid_ids.contains(&tx.id()))
                .collect::<Vec<Tx>>();

            self.handle_transactions(&transactions, height, block.time())?;
        }

        Ok(())
    }

    fn sync_all(&self) -> Result<()> {
        self.clear()?;
        self.sync()
    }

    fn transaction_changes(&self, address: &ExtendedAddr) -> Result<Vec<TransactionChange>> {
        self.address_service.get(address)
    }

    fn balance(&self, address: &ExtendedAddr) -> Result<Coin> {
        self.balance_service.get(address)
    }

    fn transaction(&self, id: &TxId) -> Result<Option<Tx>> {
        self.transaction_service.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use chain_core::init::address::RedeemAddress;

    #[test]
    fn check_flow() {
        let index = RpcSledIndex::new("./index-test".to_owned(), "dummy").unwrap();

        let spend_address = ExtendedAddr::BasicRedeem(
            RedeemAddress::from_str("1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
        );
        let view_address = ExtendedAddr::BasicRedeem(
            RedeemAddress::from_str("790661a2fd9da3fee53caab80859ecae125a20a5").unwrap(),
        );

        assert!(index.sync_all().is_ok());
        assert_eq!(Coin::zero(), index.balance(&spend_address).unwrap());
        assert_eq!(
            Coin::new(10000000000000000000).unwrap(),
            index.balance(&view_address).unwrap()
        );

        assert_eq!(2, index.transaction_changes(&spend_address).unwrap().len());
        assert_eq!(1, index.transaction_changes(&view_address).unwrap().len());

        for change in index.transaction_changes(&spend_address).unwrap().iter() {
            assert!(index.transaction(&change.transaction_id).unwrap().is_some());
        }
    }
}
