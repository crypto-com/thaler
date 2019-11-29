//! Operations on unspent transactions
use std::ops::{Deref, DerefMut};

use chain_core::init::coin::Coin;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use client_common::{Error, ErrorKind, Result, ResultExt};

/// An iterator over unspent transactions
///
/// # Usage
///
/// ```no_run
/// # use client_core::unspent_transactions::*;
/// // Retrieve a list of unspent transactions from an external source (e.g. WalletClient)
/// let mut unspent_transactions = UnspentTransactions::default();
///
/// // A list of operations to apply: transactions in decreasing order of their value.
/// let operations = &[Operation::Sort(Sorter::HighestValueFirst)];
///
/// // Apply operations
/// unspent_transactions.apply_all(operations);
/// ```
#[derive(Debug, Default, Clone)]
pub struct UnspentTransactions {
    inner: Vec<(TxoPointer, TxOut)>,
}

/// An iterator over selected unspent transactions
#[derive(Debug)]
pub struct SelectedUnspentTransactions<'a> {
    inner: &'a [(TxoPointer, TxOut)],
}

impl Deref for UnspentTransactions {
    type Target = Vec<(TxoPointer, TxOut)>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for UnspentTransactions {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a> Deref for SelectedUnspentTransactions<'a> {
    type Target = [(TxoPointer, TxOut)];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl UnspentTransactions {
    /// Creates a new instance of unspent transactions
    #[inline]
    pub fn new(unspent_transactions: Vec<(TxoPointer, TxOut)>) -> Self {
        Self {
            inner: unspent_transactions,
        }
    }

    /// Applies operations on current unspent transactions
    pub fn apply_all(&mut self, operations: &[Operation]) {
        let mut temp = UnspentTransactions::default();
        std::mem::swap(self, &mut temp);

        let mut builder = Builder::normal(temp.unwrap());

        for operation in operations {
            builder = builder.apply(*operation);
        }

        temp = builder.build();

        std::mem::swap(self, &mut temp);
    }

    /// Returns inner vector of unspent transactions
    #[inline]
    pub fn unwrap(self) -> Vec<(TxoPointer, TxOut)> {
        self.inner
    }

    /// Selects unspent transactions for given amount and returns difference amount
    pub fn select(&self, amount: Coin) -> Result<(SelectedUnspentTransactions<'_>, Coin)> {
        let mut selected_amount = Coin::zero();

        for (i, (_, unspent_transaction)) in self.inner.iter().enumerate() {
            selected_amount = (selected_amount + unspent_transaction.value).chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Total amount of selected UTXOs exceeds maximum allowed value",
                )
            })?;

            if selected_amount >= amount {
                return Ok((
                    SelectedUnspentTransactions {
                        inner: &self.inner[..=i],
                    },
                    (selected_amount - amount).chain(|| {
                        (
                            ErrorKind::IllegalInput,
                            "Amount of selected UTXOs is negative",
                        )
                    })?,
                ));
            }
        }

        Err(Error::new(ErrorKind::InvalidInput, "Insufficient balance"))
    }

    /// Selects all unspent transactions
    pub fn select_all(&self) -> SelectedUnspentTransactions<'_> {
        SelectedUnspentTransactions { inner: &self.inner }
    }
}

/// Builder for unspent transactions
enum Builder {
    Normal(Vec<(TxoPointer, TxOut)>),
}

impl Builder {
    /// Creates a new instance of normal unspent transaction builder
    #[inline]
    fn normal(unspent_transactions: Vec<(TxoPointer, TxOut)>) -> Self {
        Builder::Normal(unspent_transactions)
    }

    /// Applies sorting operation
    fn sort_by(self, sorter: Sorter) -> Self {
        match self {
            Builder::Normal(unspent_transactions) => {
                Builder::normal(sorter.sort(unspent_transactions))
            }
        }
    }

    /// Applies an operation
    fn apply(self, operation: Operation) -> Self {
        match operation {
            Operation::Sort(sort_by) => self.sort_by(sort_by),
        }
    }

    /// Freezes current builder and returns unspent transactions after applying all operations
    fn build(self) -> UnspentTransactions {
        match self {
            Builder::Normal(mut unspent_transactions) => {
                unspent_transactions.shrink_to_fit();
                UnspentTransactions::new(unspent_transactions)
            }
        }
    }
}

/// Operations on unspent transactions
#[derive(Debug, Clone, Copy)]
pub enum Operation {
    /// Sort operations
    Sort(Sorter),
}

/// Sorters for unspent transactions
#[derive(Debug, Clone, Copy)]
pub enum Sorter {
    /// Sorts unspent transactions such that ones with highest value are selected first
    HighestValueFirst,
    /// Sorts unspent transactions such that ones with highest value are selected first
    LowestValueFirst,
}

impl Sorter {
    /// Sorts unspent transactions
    fn sort(self, mut unspent_transactions: Vec<(TxoPointer, TxOut)>) -> Vec<(TxoPointer, TxOut)> {
        match self {
            Sorter::HighestValueFirst => {
                unspent_transactions.sort_by(|(_, a), (_, b)| a.value.cmp(&b.value).reverse())
            }
            Sorter::LowestValueFirst => {
                unspent_transactions.sort_by(|(_, a), (_, b)| a.value.cmp(&b.value))
            }
        }

        unspent_transactions
    }
}

#[cfg(test)]
mod unspent_transactions_tests {
    use super::*;

    use rand::random;

    use chain_core::init::coin::Coin;
    use chain_core::tx::data::address::ExtendedAddr;

    fn sample() -> UnspentTransactions {
        let mut unspent_transactions = Vec::new();

        unspent_transactions.push((
            TxoPointer::new(random(), 0),
            TxOut::new(ExtendedAddr::OrTree(random()), Coin::new(100).unwrap()),
        ));

        unspent_transactions.push((
            TxoPointer::new(random(), 0),
            TxOut::new(ExtendedAddr::OrTree(random()), Coin::new(200).unwrap()),
        ));

        unspent_transactions.push((
            TxoPointer::new(random(), 0),
            TxOut::new(ExtendedAddr::OrTree(random()), Coin::new(300).unwrap()),
        ));

        unspent_transactions.push((
            TxoPointer::new(random(), 0),
            TxOut::new(ExtendedAddr::OrTree(random()), Coin::new(150).unwrap()),
        ));

        unspent_transactions.push((
            TxoPointer::new(random(), 0),
            TxOut::new(ExtendedAddr::OrTree(random()), Coin::new(250).unwrap()),
        ));

        UnspentTransactions::new(unspent_transactions)
    }

    #[test]
    fn check_highest_value_first() {
        let operations = &[Operation::Sort(Sorter::HighestValueFirst)];
        let mut unspent_transactions = sample();
        unspent_transactions.apply_all(operations);
        assert_eq!(5, unspent_transactions.len());

        let mut coin = Coin::max();

        for (_, tx_out) in unspent_transactions.iter() {
            assert!(tx_out.value < coin);
            coin = tx_out.value;
        }
    }

    #[test]
    fn check_lowest_value_first() {
        let operations = &[Operation::Sort(Sorter::LowestValueFirst)];
        let mut unspent_transactions = sample();
        unspent_transactions.apply_all(operations);
        assert_eq!(5, unspent_transactions.len());

        let mut coin = Coin::zero();

        for (_, tx_out) in unspent_transactions.iter() {
            assert!(tx_out.value >= coin);
            coin = tx_out.value;
        }
    }
}
