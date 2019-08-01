use std::convert::TryInto;

use failure::ResultExt;
use parity_scale_codec::{Decode, Encode};

use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use chain_core::tx::TransactionId;
use client_common::{Error, ErrorKind, Result, Storage, Transaction};

const KEYSPACE: &str = "index_transaction";

/// Exposes functionalities for managing transaction storage
///
/// Stores `transaction_id -> transaction` mapping
#[derive(Default, Clone)]
pub struct TransactionService<S>
where
    S: Storage,
{
    storage: S,
}

impl<S> TransactionService<S>
where
    S: Storage,
{
    /// Creates a new instance of transaction service
    #[inline]
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Retrieves transaction with given id
    pub fn get(&self, id: &TxId) -> Result<Option<Transaction>> {
        let transaction = self
            .storage
            .get(KEYSPACE, id)?
            .map(|bytes| {
                Transaction::decode(&mut bytes.as_slice()).context(ErrorKind::DeserializationError)
            })
            .transpose()?;

        Ok(transaction)
    }

    /// Sets transaction with given id and value
    pub fn set(&self, transaction: &Transaction) -> Result<()> {
        self.storage
            .set(KEYSPACE, &transaction.id(), transaction.encode())
            .map(|_| ())
    }

    /// Retrieves transaction output corresponding to given pointer
    pub fn get_output(&self, input: &TxoPointer) -> Result<TxOut> {
        let transaction = self
            .get(&input.id)?
            .ok_or_else(|| Error::from(ErrorKind::TransactionNotFound))?;

        let outputs = match transaction {
            Transaction::TransferTransaction(transfer_transaction) => {
                Ok(transfer_transaction.outputs)
            }
            Transaction::WithdrawUnbondedStakeTransaction(withdraw_transaction) => {
                Ok(withdraw_transaction.outputs)
            }
            _ => Err(Error::from(ErrorKind::InvalidTransaction)),
        }?;

        let output = outputs
            .into_iter()
            .nth(input.index.try_into().unwrap())
            .ok_or_else(|| Error::from(ErrorKind::TransactionNotFound))?;

        Ok(output)
    }

    /// Clears all storage
    #[inline]
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chain_core::init::coin::Coin;
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::attribute::TxAttributes;
    use chain_core::tx::data::Tx;
    use client_common::storage::MemoryStorage;

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

    #[test]
    fn check_flow() {
        let storage = MemoryStorage::default();

        let transaction_service = TransactionService::new(storage);
        let transaction = transfer_transaction();
        let transaction_id = transaction.id();

        assert_eq!(None, transaction_service.get(&transaction_id).unwrap());
        assert!(transaction_service.set(&transaction).is_ok());

        assert_eq!(
            transaction,
            transaction_service.get(&transaction_id).unwrap().unwrap()
        );

        assert_eq!(
            Coin::new(100).unwrap(),
            transaction_service
                .get_output(&TxoPointer::new(transaction_id, 0))
                .unwrap()
                .value
        );

        assert!(transaction_service.clear().is_ok());
        assert_eq!(None, transaction_service.get(&transaction_id).unwrap());
    }
}
