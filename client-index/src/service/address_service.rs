use std::collections::{BTreeMap, BTreeSet, HashMap};

use parity_scale_codec::{Decode, Encode};

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use client_common::balance::TransactionChange;
use client_common::{ErrorKind, Result, ResultExt, Storage};

const KEYSPACE: &str = "index_address";

/// All the details related to an address
#[derive(Debug, Encode, Decode)]
pub struct AddressDetails {
    /// Unpent transactions corresponding to an address
    pub unspent_transactions: BTreeMap<TxoPointer, TxOut>,
    /// Transaction history corresponding to an address
    pub transaction_history: Vec<TransactionChange>,
    /// Balance of an address
    pub balance: Coin,

    /// Stores a set of transaction_ids that have been updated for current address.
    transaction_ids: BTreeSet<TxId>,
}

impl AddressDetails {
    fn apply_memento_operations(
        &mut self,
        transaction_id: TxId,
        operations: &[MementoOperation],
    ) -> Result<()> {
        if self.transaction_ids.contains(&transaction_id) {
            // Don't re-apply memento for same transaction
            return Ok(());
        }

        for operation in operations {
            self.apply_memento_operation(operation)?;
        }

        self.transaction_ids.insert(transaction_id);

        Ok(())
    }

    fn apply_memento_operation(&mut self, operation: &MementoOperation) -> Result<()> {
        match operation {
            MementoOperation::AddTransactionChange(transaction_change) => {
                self.balance = (self.balance + &transaction_change.balance_change)?;
                self.transaction_history.push((*transaction_change).clone());
            }
            MementoOperation::AddUnspentTransaction(input, output) => {
                self.unspent_transactions
                    .insert((*input).clone(), (*output).clone());
            }
            MementoOperation::RemoveUnspentTransaction(input) => {
                self.unspent_transactions.remove(input);
            }
        }

        Ok(())
    }
}

impl Default for AddressDetails {
    #[inline]
    fn default() -> Self {
        Self {
            unspent_transactions: Default::default(),
            transaction_history: Default::default(),
            balance: Coin::zero(),
            transaction_ids: Default::default(),
        }
    }
}

/// A memento for address details used for batch operations on address service
#[derive(Debug)]
pub struct AddressMemento {
    transaction_id: TxId,
    operations: HashMap<ExtendedAddr, Vec<MementoOperation>>,
}

impl AddressMemento {
    /// Creates a new instance of address memento
    #[inline]
    pub fn new(transaction_id: TxId) -> Self {
        Self {
            transaction_id,
            operations: Default::default(),
        }
    }

    /// Adds a transaction change to memento
    #[inline]
    pub fn add_transaction_change(
        &mut self,
        address: &ExtendedAddr,
        transaction_change: TransactionChange,
    ) {
        self.add_operation(
            address,
            MementoOperation::AddTransactionChange(transaction_change),
        );
    }

    /// Adds unspent transaction to memento
    #[inline]
    pub fn add_unspent_transaction(
        &mut self,
        address: &ExtendedAddr,
        input: TxoPointer,
        output: TxOut,
    ) {
        self.add_operation(
            address,
            MementoOperation::AddUnspentTransaction(input, output),
        );
    }

    /// Removes unspent transaction from memento
    #[inline]
    pub fn remove_unspent_transaction(&mut self, address: &ExtendedAddr, input: TxoPointer) {
        self.add_operation(address, MementoOperation::RemoveUnspentTransaction(input));
    }

    fn add_operation(&mut self, address: &ExtendedAddr, operation: MementoOperation) {
        if !self.operations.contains_key(address) {
            self.operations.insert(address.clone(), Default::default());
        }

        let memento_operations = self.operations.get_mut(address).unwrap();
        memento_operations.push(operation);
    }
}

#[derive(Debug, Clone)]
enum MementoOperation {
    AddTransactionChange(TransactionChange),
    AddUnspentTransaction(TxoPointer, TxOut),
    RemoveUnspentTransaction(TxoPointer),
}

/// Exposes functionality for managing storage of entities for an address
///
/// Stores `address -> address_details`
#[derive(Default, Clone)]
pub struct AddressService<S>
where
    S: Storage,
{
    storage: S,
}

impl<S> AddressService<S>
where
    S: Storage,
{
    /// Creates a new instance of address service
    #[inline]
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Retrieves details corresponding to given address
    pub fn get(&self, address: &ExtendedAddr) -> Result<AddressDetails> {
        self.storage
            .get(KEYSPACE, address.encode())?
            .map(|bytes| {
                Ok(AddressDetails::decode(&mut bytes.as_slice()).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        format!("Unable to deserialize address details for {}", address),
                    )
                })?)
            })
            .unwrap_or_else(|| Ok(Default::default()))
    }

    /// Deletes details for given address
    pub fn delete(&self, address: &ExtendedAddr) -> Result<()> {
        self.storage.delete(KEYSPACE, address.encode()).map(|_| ())
    }

    /// Applies and commits an address memento.
    ///
    /// # Transaction boundary
    ///
    /// Address memento contains operations for different addresses. Transaction isolation boundary for this
    /// memento is: operations for a single address will be isolated and atomic.
    pub fn apply_memento(&self, memento: &AddressMemento) -> Result<()> {
        let transaction_id = memento.transaction_id;

        for (address, operations) in memento.operations.iter() {
            self.storage
                .fetch_and_update(KEYSPACE, address.encode(), |value| {
                    let mut address_details = value
                        .map(|mut bytes| -> Result<AddressDetails> {
                            Ok(AddressDetails::decode(&mut bytes).chain(|| {
                                (
                                    ErrorKind::DeserializationError,
                                    "Unable to deserialize address details while applying memento",
                                )
                            })?)
                        })
                        .unwrap_or_else(|| Ok(Default::default()))?;

                    address_details.apply_memento_operations(transaction_id, operations)?;

                    Ok(Some(address_details.encode()))
                })?;
        }

        Ok(())
    }

    /// Clears all storage
    #[inline]
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}
