use std::collections::BTreeMap;

use parity_scale_codec::{Decode, Encode};
use secstr::SecUtf8;

use chain_core::{
    init::coin::Coin,
    tx::data::{input::TxoPointer, output::TxOut, TxId},
};
use client_common::{Error, ErrorKind, Result, ResultExt, SecureStorage, Storage};

use crate::types::TransactionChange;

/// key space of wallet state
const KEYSPACE: &str = "core_wallet_state";

/// Maintains mapping `wallet-name -> wallet-state`
#[derive(Debug, Default, Clone)]
pub struct WalletStateService<S>
where
    S: Storage,
{
    storage: S,
}

impl<S> WalletStateService<S>
where
    S: Storage,
{
    /// Creates new instance of global state service
    #[inline]
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Clears all storage
    #[inline]
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }

    /// Returns `true` if given transaction inputs are present in the list of unspent transactions, `false` otherwise
    pub fn has_unspent_transactions(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        inputs: &[TxoPointer],
    ) -> Result<bool> {
        let unspent_transactions = self.get_unspent_transactions(name, passphrase)?;

        Ok(inputs
            .iter()
            .all(|input| unspent_transactions.contains_key(input)))
    }

    /// Returns currently stored unspent transactions for given wallet
    #[inline]
    pub fn get_unspent_transactions(
        &self,
        name: &str,
        passphrase: &SecUtf8,
    ) -> Result<BTreeMap<TxoPointer, TxOut>> {
        self.get_wallet_state(name, passphrase)
            .map(|wallet_state| wallet_state.unspent_transactions)
    }

    /// Returns currently stored transaction history for given wallet
    #[inline]
    pub fn get_transaction_history(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        reversed: bool,
    ) -> Result<Box<dyn Iterator<Item = TransactionChange>>> {
        let mut state = self.get_wallet_state(name, passphrase)?;
        let mut history = std::mem::replace(&mut state.transaction_history, BTreeMap::new());
        let get_tx = move |txid| history.remove(&txid);
        let iter = state.transaction_log.into_iter();
        Ok(if reversed {
            Box::new(iter.rev().filter_map(get_tx))
        } else {
            Box::new(iter.filter_map(get_tx))
        })
    }

    /// Returns currently stored transaction change for given wallet and transaction id
    #[inline]
    pub fn get_transaction_change(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        transaction_id: &TxId,
    ) -> Result<Option<TransactionChange>> {
        Ok(self
            .get_wallet_state(name, passphrase)?
            .get_transaction_change(transaction_id))
    }

    /// Returns details corresponding to given input
    pub fn get_output(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        input: &TxoPointer,
    ) -> Result<Option<TxOut>> {
        self.get_wallet_state(name, passphrase)?.get_output(input)
    }

    /// Returns currently stored balance for given wallet
    #[inline]
    pub fn get_balance(&self, name: &str, passphrase: &SecUtf8) -> Result<Coin> {
        Ok(self.get_wallet_state(name, passphrase)?.balance)
    }

    fn modify_state<F>(&self, name: &str, passphrase: &SecUtf8, f: F) -> Result<()>
    where
        F: Fn(&mut WalletState) -> Result<()>,
    {
        self.storage
            .fetch_and_update_secure(KEYSPACE, name, passphrase, |bytes_optional| {
                let mut wallet_state = parse_wallet_state(name, bytes_optional)?;
                f(&mut wallet_state)?;
                Ok(Some(wallet_state.encode()))
            })
            .map(|_| ())
    }

    /// Applies and commits wallet state memento
    pub fn apply_memento(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        memento: &WalletStateMemento,
    ) -> Result<()> {
        self.modify_state(name, passphrase, |state| state.apply_memento(memento))
    }

    /// Deletes all the state data corresponding to a wallet
    #[inline]
    pub fn delete_wallet_state(&self, name: &str, passphrase: &SecUtf8) -> Result<()> {
        // Check if the passphrase is correct
        let _ = self.get_wallet_state(name, passphrase)?;
        self.storage.delete(KEYSPACE, name).map(|_| ())
    }

    #[inline]
    fn get_wallet_state(&self, name: &str, passphrase: &SecUtf8) -> Result<WalletState> {
        Ok(load_wallet_state(&self.storage, name, passphrase)?.unwrap_or_default())
    }
}

fn parse_wallet_state<T: AsRef<[u8]>>(
    name: &str,
    bytes_optional: Option<T>,
) -> Result<WalletState> {
    bytes_optional
        .map(|bytes| {
            WalletState::decode(&mut bytes.as_ref()).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!(
                        "Unable to deserialize wallet state for wallet with name {}",
                        name
                    ),
                )
            })
        })
        .transpose()
        .map(|wallet_state_optional| wallet_state_optional.unwrap_or_default())
}

/// Load wallet state from storage
pub fn load_wallet_state<S: SecureStorage>(
    storage: &S,
    name: &str,
    passphrase: &SecUtf8,
) -> Result<Option<WalletState>> {
    storage.load_secure(KEYSPACE, name, passphrase)
}

/// Save wallet state to storage
pub fn save_wallet_state<S: SecureStorage>(
    storage: &S,
    name: &str,
    passphrase: &SecUtf8,
    state: &WalletState,
) -> Result<()> {
    storage.save_secure(KEYSPACE, name, passphrase, state)
}

/// Modify wallet state atomically, and returns the new one.
pub fn modify_wallet_state<S, F>(
    storage: &S,
    name: &str,
    passphrase: &SecUtf8,
    f: F,
) -> Result<WalletState>
where
    S: SecureStorage,
    F: Fn(&mut WalletState) -> Result<()>,
{
    storage.fetch_and_update_secure(KEYSPACE, name, passphrase, |bytes_optional| {
        let mut wallet_state = parse_wallet_state(name, bytes_optional)?;
        f(&mut wallet_state)?;
        Ok(Some(wallet_state.encode()))
    })?;
    // FIXME need to modify the storage trait to save this extra loading.
    Ok(load_wallet_state(storage, name, passphrase)?.unwrap())
}

/// Delete wallet state from storage
pub fn delete_wallet_state<S: Storage>(storage: &S, name: &str) -> Result<()> {
    storage.delete(KEYSPACE, name)?;
    Ok(())
}

/// Wallet state
#[derive(Debug, Encode, Decode)]
pub struct WalletState {
    /// UTxO
    pub unspent_transactions: BTreeMap<TxoPointer, TxOut>,
    /// Transaction history indexed by txid
    pub transaction_history: BTreeMap<TxId, TransactionChange>,
    /// Transaction ids ordered by insert order.
    pub transaction_log: Vec<TxId>,
    /// Balance
    pub balance: Coin,
}

impl Default for WalletState {
    #[inline]
    fn default() -> WalletState {
        WalletState {
            unspent_transactions: Default::default(),
            transaction_history: Default::default(),
            transaction_log: vec![],
            balance: Coin::zero(),
        }
    }
}

impl WalletState {
    /// Applies memento to wallet state
    pub fn apply_memento(&mut self, memento: &WalletStateMemento) -> Result<()> {
        for operation in memento.0.iter() {
            self.apply_memento_operation(operation)?;
        }
        Ok(())
    }

    fn add_transaction_change(&mut self, txid: TxId, change: TransactionChange) {
        self.transaction_history.insert(txid, change);
        self.transaction_log.push(txid);
    }

    /// Applies a memento operation to wallet state
    fn apply_memento_operation(&mut self, memento_operation: &MementoOperation) -> Result<()> {
        match memento_operation {
            MementoOperation::AddTransactionChange(ref transaction_id, ref transaction_change) => {
                if !self.transaction_history.contains_key(transaction_id) {
                    self.balance = (self.balance + transaction_change.balance_change)?;
                    self.add_transaction_change(transaction_id.clone(), transaction_change.clone());
                }
            }
            MementoOperation::AddUnspentTransaction(ref input, ref output) => {
                self.unspent_transactions
                    .insert(input.clone(), output.clone());
            }
            MementoOperation::RemoveUnspentTransaction(ref input) => {
                self.unspent_transactions.remove(input);
            }
        }
        Ok(())
    }

    /// Returns currently stored transaction change for given wallet and transaction id
    pub fn get_transaction_change(&self, transaction_id: &TxId) -> Option<TransactionChange> {
        self.transaction_history.get(transaction_id).cloned()
    }

    /// Returns details corresponding to given input
    pub fn get_output(&self, input: &TxoPointer) -> Result<Option<TxOut>> {
        if let Some(change) = self.get_transaction_change(&input.id) {
            if change.outputs.len() > input.index as usize {
                Ok(Some(change.outputs[input.index as usize].clone()))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Index is greater than total outputs in transaction",
                ))
            }
        } else {
            Ok(None)
        }
    }
}

/// A memento for wallet state used for batch operations on wallet state service
#[derive(Debug, Default, Clone)]
pub struct WalletStateMemento(Vec<MementoOperation>);

#[derive(Debug, Clone)]
enum MementoOperation {
    AddTransactionChange(TxId, TransactionChange),
    AddUnspentTransaction(TxoPointer, TxOut),
    RemoveUnspentTransaction(TxoPointer),
}

impl WalletStateMemento {
    /// Adds transaction change to memento
    #[inline]
    pub fn add_transaction_change(&mut self, transaction_change: TransactionChange) {
        self.0.push(MementoOperation::AddTransactionChange(
            transaction_change.transaction_id,
            transaction_change,
        ))
    }

    /// Adds unspent transaction to memento
    #[inline]
    pub fn add_unspent_transaction(&mut self, input: TxoPointer, output: TxOut) {
        self.0
            .push(MementoOperation::AddUnspentTransaction(input, output))
    }

    /// Removes unspent transaction from memento
    #[inline]
    pub fn remove_unspent_transaction(&mut self, input: TxoPointer) {
        self.0
            .push(MementoOperation::RemoveUnspentTransaction(input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use chain_core::tx::data::address::ExtendedAddr;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::Time;

    use crate::types::{BalanceChange, TransactionType};

    #[test]
    fn check_wallet_state_service_flow() {
        let storage = MemoryStorage::default();
        let wallet_state_service = WalletStateService::new(storage);

        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        // Check empty state

        assert_eq!(
            0,
            wallet_state_service
                .get_unspent_transactions(name, passphrase)
                .unwrap()
                .len()
        );

        assert_eq!(
            0,
            wallet_state_service
                .get_transaction_history(name, passphrase, false)
                .unwrap()
                .count()
        );

        assert!(wallet_state_service
            .get_transaction_change(name, passphrase, &[0; 32])
            .unwrap()
            .is_none());

        assert_eq!(
            Coin::zero(),
            wallet_state_service.get_balance(name, passphrase).unwrap()
        );

        // Add an unspent transaction and check if it is added

        let mut memento = WalletStateMemento::default();

        memento.add_unspent_transaction(
            TxoPointer::new([0; 32], 0),
            TxOut::new(ExtendedAddr::OrTree([0; 32]), Coin::zero()),
        );

        assert!(wallet_state_service
            .apply_memento(name, passphrase, &memento)
            .is_ok());

        assert_eq!(
            1,
            wallet_state_service
                .get_unspent_transactions(name, passphrase)
                .unwrap()
                .len()
        );

        // Remove previously added unspent transaction and check if it is removed

        let mut memento = WalletStateMemento::default();

        memento.remove_unspent_transaction(TxoPointer::new([0; 32], 0));

        assert!(wallet_state_service
            .apply_memento(name, passphrase, &memento)
            .is_ok());

        assert_eq!(
            0,
            wallet_state_service
                .get_unspent_transactions(name, passphrase)
                .unwrap()
                .len()
        );

        // Add a transaction change (with incoming balance) and check if it is added and also new wallet balance

        let mut memento = WalletStateMemento::default();

        memento.add_transaction_change(TransactionChange {
            transaction_id: [0; 32],
            inputs: Vec::new(),
            outputs: Vec::new(),
            balance_change: BalanceChange::Incoming {
                value: Coin::new(50).unwrap(),
            },
            transaction_type: TransactionType::Transfer,
            block_height: 0,
            block_time: Time::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
        });

        assert!(wallet_state_service
            .apply_memento(name, passphrase, &memento)
            .is_ok());

        assert_eq!(
            Coin::new(50).unwrap(),
            wallet_state_service.get_balance(name, passphrase).unwrap()
        );

        assert_eq!(
            1,
            wallet_state_service
                .get_transaction_history(name, passphrase, false)
                .unwrap()
                .count()
        );

        assert!(wallet_state_service
            .get_transaction_change(name, passphrase, &[0; 32])
            .unwrap()
            .is_some());

        assert!(wallet_state_service
            .get_transaction_change(name, passphrase, &[1; 32])
            .unwrap()
            .is_none());

        // Add a transaction change (with outgoing balance) and check if it is added and also new wallet balance

        let mut memento = WalletStateMemento::default();

        memento.add_transaction_change(TransactionChange {
            transaction_id: [1; 32],
            inputs: Vec::new(),
            outputs: Vec::new(),
            balance_change: BalanceChange::Outgoing {
                value: Coin::new(40).unwrap(),
                fee: Coin::new(10).unwrap(),
            },
            transaction_type: TransactionType::Transfer,
            block_height: 0,
            block_time: Time::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
        });

        assert!(wallet_state_service
            .apply_memento(name, passphrase, &memento)
            .is_ok());

        assert_eq!(
            Coin::zero(),
            wallet_state_service.get_balance(name, passphrase).unwrap()
        );

        assert_eq!(
            2,
            wallet_state_service
                .get_transaction_history(name, passphrase, false)
                .unwrap()
                .count()
        );

        assert!(wallet_state_service
            .get_transaction_change(name, passphrase, &[1; 32])
            .unwrap()
            .is_some());
    }
}
