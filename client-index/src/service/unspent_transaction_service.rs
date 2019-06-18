use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use client_common::{ErrorKind, Result, Storage};
use parity_codec::{Decode, Encode};

const KEYSPACE: &str = "index_unspent_transaction";
/// Exposes functionalities for managing unspent transactions
///
/// Stores `address -> [(TxoPointer, TxOut)]` mapping
#[derive(Default, Clone)]
pub struct UnspentTransactionService<S: Storage> {
    storage: S,
}

impl<S> UnspentTransactionService<S>
where
    S: Storage,
{
    /// Creates a new instance of unspent transaction service
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Retrieves all the unspent transactions for an address
    pub fn get(&self, address: &ExtendedAddr) -> Result<Vec<(TxoPointer, TxOut)>> {
        self.storage
            .get(KEYSPACE, address.encode())?
            .map(|bytes| {
                Ok(Vec::decode(&mut bytes.as_slice()).ok_or(ErrorKind::DeserializationError)?)
            })
            .unwrap_or_else(|| Ok(Default::default()))
    }

    /// Adds an unspent transactions to storage
    pub fn add(
        &self,
        address: &ExtendedAddr,
        unspent_transaction: (&TxoPointer, &TxOut),
    ) -> Result<()> {
        self.storage
            .fetch_and_update(KEYSPACE, address.encode(), |value| {
                let mut unspent_transactions = value
                    .map(|mut bytes| -> Result<Vec<(TxoPointer, TxOut)>> {
                        Ok(Vec::decode(&mut bytes).ok_or(ErrorKind::DeserializationError)?)
                    })
                    .unwrap_or_else(|| Ok(Default::default()))?;
                unspent_transactions
                    .push((unspent_transaction.0.clone(), unspent_transaction.1.clone()));

                Ok(Some(unspent_transactions.encode()))
            })
            .map(|_| ())
    }

    /// Removes an unspent transaction for given address
    pub fn remove(&self, address: &ExtendedAddr, pointer: &TxoPointer) -> Result<()> {
        self.storage
            .fetch_and_update(KEYSPACE, address.encode(), |value| {
                let mut unspent_transactions = value
                    .map(|mut bytes| -> Result<Vec<(TxoPointer, TxOut)>> {
                        Ok(Vec::decode(&mut bytes).ok_or(ErrorKind::DeserializationError)?)
                    })
                    .unwrap_or_else(|| Ok(Default::default()))?;

                let mut index = None;

                for (i, (tx_pointer, _)) in unspent_transactions.iter().enumerate() {
                    if tx_pointer == pointer {
                        index = Some(i);
                        break;
                    }
                }

                if index.is_some() {
                    unspent_transactions.remove(index.unwrap());
                }

                Ok(Some(unspent_transactions.encode()))
            })
            .map(|_| ())
    }
}
