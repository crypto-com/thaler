use chrono::{DateTime, Utc};

use chain_core::state::account::{DepositBondTx, WithdrawUnbondedTx};
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::TransactionId;
use client_common::balance::{BalanceChange, TransactionChange};
use client_common::{Result, Storage, Transaction};

use crate::service::{AddressService, TransactionService};
use crate::{AddressMemento, TransactionHandler};

/// Default implementation of `TransactionHandler`
#[derive(Clone)]
pub struct DefaultTransactionHandler<S>
where
    S: Storage,
{
    transaction_service: TransactionService<S>,
    address_service: AddressService<S>,
}

impl<S> DefaultTransactionHandler<S>
where
    S: Storage + Clone,
{
    /// Creates a new instance of `DefaultTransactionHandler`
    #[inline]
    pub fn new(storage: S) -> Self {
        Self {
            transaction_service: TransactionService::new(storage.clone()),
            address_service: AddressService::new(storage),
        }
    }
}

impl<S> DefaultTransactionHandler<S>
where
    S: Storage,
{
    fn on_transfer_transaction(
        &self,
        transaction: Tx,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<()> {
        let transaction_id = transaction.id();
        let mut memento = AddressMemento::new(transaction_id);

        for input in transaction.inputs.into_iter() {
            self.handle_transaction_input(
                &mut memento,
                transaction_id,
                input,
                block_height,
                block_time,
            )?;
        }

        for (i, output) in transaction.outputs.into_iter().enumerate() {
            self.handle_transaction_output(
                &mut memento,
                transaction_id,
                output,
                i,
                block_height,
                block_time,
            );
        }

        self.address_service.apply_memento(&memento)
    }

    fn on_deposit_stake_transaction(
        &self,
        transaction: DepositBondTx,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<()> {
        let transaction_id = transaction.id();
        let mut memento = AddressMemento::new(transaction_id);

        for input in transaction.inputs.into_iter() {
            self.handle_transaction_input(
                &mut memento,
                transaction_id,
                input,
                block_height,
                block_time,
            )?;
        }

        self.address_service.apply_memento(&memento)
    }

    fn on_withdraw_unbonded_stake_transaction(
        &self,
        transaction: WithdrawUnbondedTx,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<()> {
        let transaction_id = transaction.id();
        let mut memento = AddressMemento::new(transaction_id);

        for (i, output) in transaction.outputs.into_iter().enumerate() {
            self.handle_transaction_output(
                &mut memento,
                transaction_id,
                output,
                i,
                block_height,
                block_time,
            );
        }

        self.address_service.apply_memento(&memento)
    }

    fn handle_transaction_input(
        &self,
        memento: &mut AddressMemento,
        transaction_id: TxId,
        input: TxoPointer,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<()> {
        let output = self.transaction_service.get_output(&input)?;

        let change = TransactionChange {
            transaction_id,
            address: output.address,
            balance_change: BalanceChange::Outgoing(output.value),
            block_height,
            block_time,
        };

        let address = change.address.clone();

        // Update transaction history and balance
        memento.add_transaction_change(&address, change);

        // Update unspent transactions
        memento.remove_unspent_transaction(&address, input);

        Ok(())
    }

    fn handle_transaction_output(
        &self,
        memento: &mut AddressMemento,
        transaction_id: TxId,
        output: TxOut,
        index: usize,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) {
        let change = TransactionChange {
            transaction_id,
            address: output.address.clone(),
            balance_change: BalanceChange::Incoming(output.value),
            block_height,
            block_time,
        };

        let address = change.address.clone();

        // Update transaction history and balance
        memento.add_transaction_change(&address, change);

        // Update unspent transactions
        memento.add_unspent_transaction(&address, TxoPointer::new(transaction_id, index), output);
    }
}

impl<S> TransactionHandler for DefaultTransactionHandler<S>
where
    S: Storage,
{
    fn on_next(
        &self,
        transaction: Transaction,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<()> {
        self.transaction_service.set(&transaction)?;

        match transaction {
            Transaction::TransferTransaction(transaction) => {
                self.on_transfer_transaction(transaction, block_height, block_time)
            }
            Transaction::DepositStakeTransaction(transaction) => {
                self.on_deposit_stake_transaction(transaction, block_height, block_time)
            }
            Transaction::UnbondStakeTransaction(_) => {
                // Do nothing
                Ok(())
            }
            Transaction::WithdrawUnbondedStakeTransaction(transaction) => {
                self.on_withdraw_unbonded_stake_transaction(transaction, block_height, block_time)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use chain_core::init::coin::Coin;
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::attribute::TxAttributes;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;
    use client_common::tendermint::Client;

    use crate::index::{DefaultIndex, Index};

    struct MockClient;

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<Status> {
            unreachable!()
        }

        fn block(&self, _height: u64) -> Result<Block> {
            unreachable!()
        }

        fn block_batch<T: Iterator<Item = u64>>(&self, _heights: T) -> Result<Vec<Block>> {
            unreachable!()
        }

        fn block_results(&self, _height: u64) -> Result<BlockResults> {
            unreachable!()
        }

        fn block_results_batch<T: Iterator<Item = u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<BlockResults>> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<BroadcastTxResult> {
            unreachable!()
        }

        fn query(&self, _path: &str, _data: &[u8]) -> Result<QueryResult> {
            unreachable!()
        }
    }

    fn transfer_transactions() -> [Transaction; 2] {
        let transaction1 = Transaction::TransferTransaction(Tx::new_with(
            Vec::new(),
            vec![TxOut::new(
                ExtendedAddr::OrTree([0; 32]),
                Coin::new(100).unwrap(),
            )],
            TxAttributes::default(),
        ));

        let transaction2 = Transaction::TransferTransaction(Tx::new_with(
            vec![TxoPointer::new(transaction1.id(), 0)],
            vec![TxOut::new(
                ExtendedAddr::OrTree([1; 32]),
                Coin::new(100).unwrap(),
            )],
            TxAttributes::default(),
        ));

        [transaction1, transaction2]
    }

    #[test]
    fn check_transfer_transaction_flow() {
        let storage = MemoryStorage::default();

        let index = DefaultIndex::new(storage.clone(), MockClient);
        let transaction_handler = DefaultTransactionHandler::new(storage);

        let transactions = transfer_transactions();

        transaction_handler
            .on_next(
                transactions[0].clone(),
                0,
                DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
            )
            .unwrap();

        assert_eq!(
            Coin::new(100).unwrap(),
            index
                .address_details(&ExtendedAddr::OrTree([0; 32]))
                .unwrap()
                .balance
        );

        assert_eq!(
            1,
            index
                .address_details(&ExtendedAddr::OrTree([0; 32]))
                .unwrap()
                .transaction_history
                .len()
        );

        assert_eq!(
            1,
            index
                .address_details(&ExtendedAddr::OrTree([0; 32]))
                .unwrap()
                .unspent_transactions
                .len()
        );

        transaction_handler
            .on_next(
                transactions[1].clone(),
                0,
                DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
            )
            .unwrap();

        assert_eq!(
            Coin::zero(),
            index
                .address_details(&ExtendedAddr::OrTree([0; 32]))
                .unwrap()
                .balance
        );

        assert_eq!(
            Coin::new(100).unwrap(),
            index
                .address_details(&ExtendedAddr::OrTree([1; 32]))
                .unwrap()
                .balance
        );

        assert_eq!(
            2,
            index
                .address_details(&ExtendedAddr::OrTree([0; 32]))
                .unwrap()
                .transaction_history
                .len()
        );

        assert_eq!(
            1,
            index
                .address_details(&ExtendedAddr::OrTree([1; 32]))
                .unwrap()
                .transaction_history
                .len()
        );

        assert_eq!(
            0,
            index
                .address_details(&ExtendedAddr::OrTree([0; 32]))
                .unwrap()
                .unspent_transactions
                .len()
        );

        assert_eq!(
            1,
            index
                .address_details(&ExtendedAddr::OrTree([1; 32]))
                .unwrap()
                .unspent_transactions
                .len()
        );
    }
}
