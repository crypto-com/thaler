use chrono::{DateTime, Utc};

use chain_core::tx::TransactionId;
use client_common::{BlockHeader, PrivateKey, PublicKey, Result, Storage, Transaction};

use crate::service::{GlobalStateService, TransactionService};
use crate::{BlockHandler, TransactionCipher, TransactionHandler};

/// Default implementation of `BlockHandler`
pub struct DefaultBlockHandler<C, H, S>
where
    C: TransactionCipher,
    H: TransactionHandler,
    S: Storage,
{
    transaction_cipher: C,
    transaction_handler: H,

    transaction_service: TransactionService<S>,
    global_state_service: GlobalStateService<S>,
}

impl<C, H, S> DefaultBlockHandler<C, H, S>
where
    C: TransactionCipher,
    H: TransactionHandler,
    S: Storage + Clone,
{
    /// Creates a new instance of `DefaultBlockHandler`
    #[inline]
    pub fn new(transaction_cipher: C, transaction_handler: H, storage: S) -> Self {
        Self {
            transaction_cipher,
            transaction_handler,
            transaction_service: TransactionService::new(storage.clone()),
            global_state_service: GlobalStateService::new(storage),
        }
    }
}

impl<C, H, S> DefaultBlockHandler<C, H, S>
where
    C: TransactionCipher,
    H: TransactionHandler,
    S: Storage,
{
    fn on_transaction(
        &self,
        transaction: Transaction,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<()> {
        self.transaction_service.set(&transaction)?;

        self.transaction_handler
            .on_next(transaction, block_height, block_time)
    }
}

impl<C, H, S> BlockHandler for DefaultBlockHandler<C, H, S>
where
    C: TransactionCipher,
    H: TransactionHandler,
    S: Storage,
{
    fn on_next(
        &self,
        block_header: BlockHeader,
        view_key: &PublicKey,
        private_key: &PrivateKey,
    ) -> Result<()> {
        for transaction in block_header.unencrypted_transactions {
            if block_header.transaction_ids.contains(&transaction.id()) {
                self.on_transaction(
                    transaction,
                    block_header.block_height,
                    block_header.block_time,
                )?;
            }
        }

        if block_header.block_filter.check_view_key(&view_key.into()) {
            let transactions = self
                .transaction_cipher
                .decrypt(&block_header.transaction_ids, private_key)?;

            for transaction in transactions {
                self.on_transaction(
                    transaction,
                    block_header.block_height,
                    block_header.block_time,
                )?;
            }
        }

        self.global_state_service
            .set_last_block_height(view_key, block_header.block_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use chrono::{DateTime, Utc};

    use chain_core::init::coin::Coin;
    use chain_core::state::account::{StakedStateOpAttributes, UnbondTx};
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::attribute::TxAttributes;
    use chain_core::tx::data::output::TxOut;
    use chain_core::tx::data::{Tx, TxId};
    use chain_core::tx::{TransactionId, TxAux};
    use chain_tx_filter::BlockFilter;
    use client_common::storage::MemoryStorage;
    use client_common::{SignedTransaction, Transaction};

    struct MockTransactionCipher;

    impl TransactionCipher for MockTransactionCipher {
        fn decrypt(
            &self,
            transaction_ids: &[TxId],
            _private_key: &PrivateKey,
        ) -> Result<Vec<Transaction>> {
            assert_eq!(2, transaction_ids.len());
            assert_eq!(transfer_transaction().id(), transaction_ids[0]);
            assert_eq!(unbond_transaction().id(), transaction_ids[1]);
            Ok(vec![transfer_transaction()])
        }

        fn encrypt(&self, _transaction: SignedTransaction) -> Result<TxAux> {
            unreachable!()
        }
    }

    struct MockTransactionHandler;

    impl TransactionHandler for MockTransactionHandler {
        fn on_next(
            &self,
            transaction: Transaction,
            block_height: u64,
            block_time: DateTime<Utc>,
        ) -> Result<()> {
            if transaction != transfer_transaction() && transaction != unbond_transaction() {
                panic!("Invalid transaction")
            }
            assert_eq!(1, block_height);
            assert_eq!(
                <DateTime<Utc>>::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                block_time
            );
            Ok(())
        }
    }

    fn transfer_transaction() -> Transaction {
        Transaction::TransferTransaction(Tx::new_with(
            Vec::new(),
            vec![TxOut::new(
                ExtendedAddr::OrTree([0; 32]),
                Coin::new(100).unwrap(),
            )],
            TxAttributes::default(),
        ))
    }

    fn unbond_transaction() -> Transaction {
        Transaction::UnbondStakeTransaction(UnbondTx::new(
            Coin::new(100).unwrap(),
            0,
            StakedStateOpAttributes::new(0),
        ))
    }

    fn block_header(view_key: &PublicKey) -> BlockHeader {
        let transaction_ids: Vec<TxId> =
            vec![transfer_transaction().id(), unbond_transaction().id()];

        let mut block_filter = BlockFilter::default();
        block_filter.add_view_key(&view_key.into());

        BlockHeader {
            block_height: 1,
            block_time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
            transaction_ids,
            block_filter,
            unencrypted_transactions: vec![unbond_transaction()],
        }
    }

    #[test]
    fn check_block_flow() {
        let storage = MemoryStorage::default();

        let private_key = PrivateKey::new().unwrap();
        let view_key = PublicKey::from(&private_key);

        let block_header = block_header(&view_key);

        let block_handler = DefaultBlockHandler::new(
            MockTransactionCipher,
            MockTransactionHandler,
            storage.clone(),
        );

        let transaction_service = TransactionService::new(storage.clone());
        let global_state_service = GlobalStateService::new(storage);

        let transaction = transfer_transaction();
        let unbond_transaction = unbond_transaction();

        assert!(transaction_service
            .get(&transaction.id())
            .unwrap()
            .is_none());
        assert_eq!(
            0,
            global_state_service.last_block_height(&view_key).unwrap()
        );

        block_handler
            .on_next(block_header, &view_key, &private_key)
            .unwrap();

        assert_eq!(
            transaction,
            transaction_service.get(&transaction.id()).unwrap().unwrap()
        );
        assert_eq!(
            unbond_transaction,
            transaction_service
                .get(&unbond_transaction.id())
                .unwrap()
                .unwrap()
        );
        assert_eq!(
            1,
            global_state_service.last_block_height(&view_key).unwrap()
        );
    }
}
