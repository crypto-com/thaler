use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use client_common::serializable::SerializableCoin;
use client_common::{ErrorKind, Result, Storage};
use parity_codec::{Decode, Encode};

const KEYSPACE: &str = "index_unspent_transaction";
/// Exposes functionalities for managing unspent transactions
///
/// Stores `address -> [(TxoPointer, SerializableCoin)]` mapping
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
    pub fn get(&self, address: &ExtendedAddr) -> Result<Vec<(TxoPointer, SerializableCoin)>> {
        let bytes = self.storage.get(KEYSPACE, address.encode())?;

        match bytes {
            None => Ok(Default::default()),
            Some(bytes) => {
                Ok(Vec::decode(&mut bytes.as_slice()).ok_or(ErrorKind::DeserializationError)?)
            }
        }
    }

    /// Adds an unspent transactions to storage
    pub fn add(
        &self,
        address: &ExtendedAddr,
        unspent_transaction: (TxoPointer, SerializableCoin),
    ) -> Result<()> {
        let mut unspent_transactions = self.get(address)?;
        unspent_transactions.push(unspent_transaction);

        self.storage
            .set(KEYSPACE, address.encode(), unspent_transactions.encode())
            .map(|_| ())
    }

    /// Removes an unspent transaction for given address
    pub fn remove(&self, address: &ExtendedAddr, pointer: &TxoPointer) -> Result<()> {
        let mut unspent_transactions = self.get(address)?;
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

        self.storage
            .set(KEYSPACE, address.encode(), unspent_transactions.encode())
            .map(|_| ())
    }
}
