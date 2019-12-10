use secstr::SecUtf8;

use chain_core::tx::TransactionId;
use client_common::{BlockHeader, ErrorKind, Result, ResultExt, Storage};

use crate::service::{KeyService, WalletService};
use crate::{BlockHandler, TransactionHandler, TransactionObfuscation};

/// Default implementation of `BlockHandler`
#[derive(Clone)]
pub struct DefaultBlockHandler<O, H, S>
where
    O: TransactionObfuscation,
    H: TransactionHandler,
    S: Storage,
{
    transaction_obfuscation: O,
    transaction_handler: H,

    key_service: KeyService<S>,
    wallet_service: WalletService<S>,
}

impl<O, H, S> DefaultBlockHandler<O, H, S>
where
    O: TransactionObfuscation,
    H: TransactionHandler,
    S: Storage + Clone,
{
    /// Creates a new instance of `DefaultBlockHandler`
    #[inline]
    pub fn new(transaction_obfuscation: O, transaction_handler: H, storage: S) -> Self {
        Self {
            transaction_obfuscation,
            transaction_handler,
            key_service: KeyService::new(storage.clone()),
            wallet_service: WalletService::new(storage.clone()),
        }
    }
}

impl<C, H, S> BlockHandler for DefaultBlockHandler<C, H, S>
where
    C: TransactionObfuscation,
    H: TransactionHandler,
    S: Storage,
{
    fn on_next(&self, name: &str, passphrase: &SecUtf8, block_header: &BlockHeader) -> Result<()> {
        for transaction in block_header.unencrypted_transactions.iter() {
            if block_header.transaction_ids.contains(&transaction.id()) {
                self.transaction_handler.on_next(
                    name,
                    passphrase,
                    transaction,
                    block_header.block_height,
                    block_header.block_time,
                )?;
            }
        }

        let view_key = self.wallet_service.view_key(name, passphrase)?;

        if block_header
            .block_filter
            .check_view_key(&view_key.clone().into())
        {
            let private_key = self
                .key_service
                .private_key(&view_key, passphrase)?
                .chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        format!(
                            "Private key corresponding to wallet's ({}) view key not found",
                            name
                        ),
                    )
                })?;

            let transactions = self
                .transaction_obfuscation
                .decrypt(&block_header.enclave_transaction_ids, &private_key)?;

            for transaction in transactions.iter() {
                self.transaction_handler.on_next(
                    name,
                    passphrase,
                    transaction,
                    block_header.block_height,
                    block_header.block_time,
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::state::account::{StakedStateAddress, StakedStateOpAttributes, UnbondTx};
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::attribute::TxAttributes;
    use chain_core::tx::data::output::TxOut;
    use chain_core::tx::data::{Tx, TxId};
    use chain_core::tx::{TransactionId, TxAux};
    use chain_tx_filter::BlockFilter;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::Time;
    use client_common::{PrivateKey, PublicKey, SignedTransaction, Transaction};

    use crate::types::WalletKind;
    use crate::wallet::{DefaultWalletClient, WalletClient};

    struct MockTransactionCipher;

    impl TransactionObfuscation for MockTransactionCipher {
        fn decrypt(
            &self,
            transaction_ids: &[TxId],
            _private_key: &PrivateKey,
        ) -> Result<Vec<Transaction>> {
            assert_eq!(1, transaction_ids.len());
            assert_eq!(transfer_transaction().id(), transaction_ids[0]);
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
            _name: &str,
            _passphrase: &SecUtf8,
            transaction: &Transaction,
            block_height: u64,
            block_time: Time,
        ) -> Result<()> {
            if transaction != &transfer_transaction() && transaction != &unbond_transaction() {
                panic!("Invalid transaction")
            }
            assert_eq!(1, block_height);
            assert_eq!(
                Time::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
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
        let addr = StakedStateAddress::from(
            RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap(),
        );
        Transaction::UnbondStakeTransaction(UnbondTx::new(
            addr,
            0,
            Coin::new(100).unwrap(),
            StakedStateOpAttributes::new(0),
        ))
    }

    fn block_header(view_key: &PublicKey) -> BlockHeader {
        let transaction_ids: Vec<TxId> =
            vec![transfer_transaction().id(), unbond_transaction().id()];

        let mut block_filter = BlockFilter::default();
        block_filter.add_view_key(&view_key.into());

        BlockHeader {
            app_hash: "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C".to_owned(),
            block_height: 1,
            block_time: Time::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
            transaction_ids,
            enclave_transaction_ids: vec![transfer_transaction().id()],
            block_filter,
            unencrypted_transactions: vec![unbond_transaction()],
        }
    }

    #[test]
    fn check_block_flow() {
        let storage = MemoryStorage::default();

        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let wallet = DefaultWalletClient::new_read_only(storage.clone());

        assert!(wallet
            .new_wallet(name, passphrase, WalletKind::Basic)
            .is_ok());

        let block_header = block_header(&wallet.view_key(name, passphrase).unwrap());

        let block_handler = DefaultBlockHandler::new(
            MockTransactionCipher,
            MockTransactionHandler,
            storage.clone(),
        );

        block_handler
            .on_next(name, passphrase, &block_header)
            .unwrap();
    }
}
