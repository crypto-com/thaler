use chrono::offset::Utc;
use chrono::DateTime;

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::TxAux;
use client_common::balance::{BalanceChange, TransactionChange};
use client_common::tendermint::Client;
use client_common::{ErrorKind, Result, Storage};

use crate::service::*;
use crate::Index;

/// Default implementation of transaction index using `Storage` and `TendermintClient`
#[derive(Default, Clone)]
pub struct DefaultIndex<S, C>
where
    S: Storage,
    C: Client,
{
    address_service: AddressService<S>,
    balance_service: BalanceService<S>,
    global_state_service: GlobalStateService<S>,
    transaction_service: TransactionService<S>,
    client: C,
}

impl<S, C> DefaultIndex<S, C>
where
    S: Storage + Clone,
    C: Client,
{
    /// Creates a new instance of `DefaultIndex`
    pub fn new(storage: S, client: C) -> Self {
        Self {
            address_service: AddressService::new(storage.clone()),
            balance_service: BalanceService::new(storage.clone()),
            global_state_service: GlobalStateService::new(storage.clone()),
            transaction_service: TransactionService::new(storage),
            client,
        }
    }
}

impl<S, C> DefaultIndex<S, C>
where
    S: Storage,
    C: Client,
{
    /// Clears all the services
    fn clear(&self) -> Result<()> {
        self.address_service.clear()?;
        self.balance_service.clear()?;
        self.global_state_service.clear()?;
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
                let transaction = self.transaction_service.get(&input.id)?;

                match transaction {
                    None => return Err(ErrorKind::InvalidTransaction.into()),
                    Some(transaction) => {
                        let index = input.index;
                        let input = transaction.outputs.into_iter().nth(index);

                        match input {
                            None => return Err(ErrorKind::InvalidTransaction.into()),
                            Some(input) => changes.push(TransactionChange {
                                transaction_id: id,
                                address: input.address,
                                balance_change: BalanceChange::Outgoing(input.value),
                                height,
                                time,
                            }),
                        }
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

impl<S, C> Index for DefaultIndex<S, C>
where
    S: Storage,
    C: Client,
{
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

    fn output(&self, id: &TxId, index: usize) -> Result<TxOut> {
        match self.transaction(id)? {
            None => Err(ErrorKind::TransactionNotFound.into()),
            Some(transaction) => match transaction.outputs.into_iter().nth(index) {
                None => Err(ErrorKind::TransactionNotFound.into()),
                Some(output) => Ok(output),
            },
        }
    }

    fn broadcast_transaction(&self, transaction: &[u8]) -> Result<()> {
        self.client.broadcast_transaction(transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use chrono::DateTime;

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::init::config::{ERC20Owner, InitConfig};
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;

    /// Mock tendermint client
    #[derive(Default, Clone)]
    pub struct MockClient;

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            Ok(Genesis {
                genesis: GenesisInner {
                    genesis_time: DateTime::from_str("2019-04-09T09:33:10.592188Z").unwrap(),
                    chain_id: "test-chain-4UIy1Wab".to_owned(),
                    app_state: InitConfig::new(vec![ERC20Owner::new(
                        RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971")
                            .unwrap(),
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
                header: Header {
                    height: "1".to_owned(),
                    time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                },
                data: Data {
                    txs: Some(vec!["+JWA+Erj4qBySKi4J+krjuZi++QuAnQITDv9YzjXV0RcDuk+S7pMeIDh4NaAlHkGYaL9naP+5TyquAhZ7K4SWiCliAAA6IkEI8eKw4GrwPhG+ESAAbhASZdu2rJI4Et7q93KedoEsTVFUOCPt8nyY0pGOqixhI4TvORYPVFmJiG+Lsr6L1wmwBLIwxJenWTyKZ8rKrwfkg==".to_owned()])
                }
            }
        })
        }

        fn block_results(&self, _: u64) -> Result<BlockResults> {
            Ok(BlockResults {
                height: "2".to_owned(),
                results: Results {
                    deliver_tx: Some(vec![DeliverTx {
                        tags: vec![Tag {
                            key: "dHhpZA==".to_owned(),
                            value: "kOzcmhZgAAaw5roBdqDNniwRjjKNe+foJEiDAOObTDQ=".to_owned(),
                        }],
                    }]),
                },
            })
        }

        fn broadcast_transaction(&self, _: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn check_flow() {
        let index = DefaultIndex::new(MemoryStorage::default(), MockClient::default());

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
            assert!(index.output(&change.transaction_id, 0).is_ok());
        }
    }
}
