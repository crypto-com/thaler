//! Operations on unspent transactions
use std::ops::{Deref, DerefMut};

use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;

/// An iterator over unspent transactions
///
/// # Usage
///
/// ```no_run
/// # use client_core::unspent_transactions::*;
/// // Retrieve a list of unspent transactions from an external source (e.g. WalletClient)
/// let mut unspent_transactions = UnspentTransactions::default();
///
/// // A list of operations to apply: only transactions with redeem addresses and in
/// // decreasing order of their value.
/// let operations = &[Operation::Filter(Filter::OnlyRedeemAddresses),
///     Operation::Sort(Sorter::HighestValueFirst)];
///
/// // Apply operations
/// unspent_transactions.apply_all(operations);
/// ```
#[derive(Debug, Default)]
pub struct UnspentTransactions {
    inner: Vec<(TxoPointer, TxOut)>,
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

        let mut builder = Builder::new(temp.unwrap());

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
}

/// Builder for unspent transactions
struct Builder {
    inner: Inner,
}

enum Inner {
    Normal(Vec<(TxoPointer, TxOut)>),
    Grouped(Box<Builder>, Box<Builder>),
}

impl Builder {
    /// Creates a new instance of unspent transaction builder
    #[inline]
    fn new(unspent_transactions: Vec<(TxoPointer, TxOut)>) -> Self {
        Self {
            inner: Inner::Normal(unspent_transactions),
        }
    }

    /// Applies sorting operation
    fn sort_by(&mut self, sorter: Sorter) {
        match self.inner {
            Inner::Normal(ref mut unspent_transactions) => sorter.sort(unspent_transactions),
            Inner::Grouped(ref mut left, ref mut right) => {
                left.sort_by(sorter);
                right.sort_by(sorter);
            }
        }
    }

    /// Applies filtering operation
    fn filter_by(&mut self, filter: Filter) {
        match self.inner {
            Inner::Normal(ref mut unspent_transactions) => filter.filter(unspent_transactions),
            Inner::Grouped(ref mut left, ref mut right) => {
                left.filter_by(filter);
                right.filter_by(filter);
            }
        }
    }

    /// Applies grouping operation
    fn group_by(&mut self, group_by: GroupBy) {
        let mut temp = Inner::Normal(Vec::new());
        std::mem::swap(&mut self.inner, &mut temp);

        let (left, right) = match temp {
            Inner::Normal(unspent_transactions) => {
                let (left, right) = group_by.group_by(unspent_transactions);
                (
                    Box::new(Builder {
                        inner: Inner::Normal(left),
                    }),
                    Box::new(Builder {
                        inner: Inner::Normal(right),
                    }),
                )
            }
            Inner::Grouped(mut left, mut right) => {
                left.group_by(group_by);
                right.group_by(group_by);

                (left, right)
            }
        };

        self.inner = Inner::Grouped(left, right);
    }

    /// Applies an operation
    fn apply(mut self, operation: Operation) -> Self {
        match operation {
            Operation::Filter(filter_by) => self.filter_by(filter_by),
            Operation::Sort(sort_by) => self.sort_by(sort_by),
            Operation::Group(group_by) => self.group_by(group_by),
        }

        self
    }

    /// Freezes current builder and returns unspent transactions after applying all operations
    fn build(self) -> UnspentTransactions {
        match self.inner {
            Inner::Normal(mut unspent_transactions) => {
                unspent_transactions.shrink_to_fit();
                UnspentTransactions {
                    inner: unspent_transactions,
                }
            }
            Inner::Grouped(left, right) => {
                let left: Builder = *left;
                let right: Builder = *right;

                let mut unspent_transactions = left.build();
                unspent_transactions.extend(right.build().unwrap());
                unspent_transactions.shrink_to_fit();
                unspent_transactions
            }
        }
    }
}

/// Operations on unspent transactions
#[derive(Debug, Clone, Copy)]
pub enum Operation {
    /// Filter operations
    Filter(Filter),
    /// Sort operations
    Sort(Sorter),
    /// Grouping operations
    Group(GroupBy),
}

/// Filters for unspent transactions
#[derive(Debug, Clone, Copy)]
pub enum Filter {
    /// Filters out all the unspent transactions without redeem addresses
    OnlyRedeemAddresses,
    /// Filters out all the unspent transactions without tree addresses
    OnlyTreeAddresses,
}

impl Filter {
    /// Filters unspent transactions
    fn filter(self, unspent_transactions: &mut Vec<(TxoPointer, TxOut)>) {
        match self {
            Filter::OnlyRedeemAddresses => unspent_transactions
                .retain(|(_, unspent_transaction)| unspent_transaction.address.is_redeem()),
            Filter::OnlyTreeAddresses => unspent_transactions
                .retain(|(_, unspent_transaction)| unspent_transaction.address.is_tree()),
        }
    }
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
    fn sort(self, unspent_transactions: &mut Vec<(TxoPointer, TxOut)>) {
        match self {
            Sorter::HighestValueFirst => {
                unspent_transactions.sort_by(|(_, a), (_, b)| a.value.cmp(&b.value).reverse())
            }
            Sorter::LowestValueFirst => {
                unspent_transactions.sort_by(|(_, a), (_, b)| a.value.cmp(&b.value))
            }
        }
    }
}

/// Grouping clause for unspent transactions
#[derive(Debug, Clone, Copy)]
pub enum GroupBy {
    /// Groups unspent transactions by address type
    AddressType(AddressTypeOrder),
}

impl GroupBy {
    /// Groups unspent transactions
    #[allow(clippy::type_complexity)]
    fn group_by(
        self,
        unspent_transactions: Vec<(TxoPointer, TxOut)>,
    ) -> (Vec<(TxoPointer, TxOut)>, Vec<(TxoPointer, TxOut)>) {
        let mut left = Vec::new();
        let mut right = Vec::new();

        match self {
            GroupBy::AddressType(AddressTypeOrder::RedeemAddressFirst) => unspent_transactions
                .into_iter()
                .for_each(|(txo_pointer, tx_out)| {
                    if tx_out.address.is_redeem() {
                        left.push((txo_pointer, tx_out));
                    } else {
                        right.push((txo_pointer, tx_out))
                    }
                }),
            GroupBy::AddressType(AddressTypeOrder::TreeAddressFirst) => unspent_transactions
                .into_iter()
                .for_each(|(txo_pointer, tx_out)| {
                    if tx_out.address.is_redeem() {
                        right.push((txo_pointer, tx_out));
                    } else {
                        left.push((txo_pointer, tx_out))
                    }
                }),
        }

        (left, right)
    }
}

/// Ordering clause for address type groups in unspent transactions
#[derive(Debug, Clone, Copy)]
pub enum AddressTypeOrder {
    /// Orders groups such that redeem address comes first
    RedeemAddressFirst,
    /// Orders groups such that tree address comes first
    TreeAddressFirst,
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::random;

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::tx::data::address::ExtendedAddr;

    use crate::{PrivateKey, PublicKey};

    fn sample() -> UnspentTransactions {
        let mut unspent_transactions = Vec::new();

        unspent_transactions.push((
            TxoPointer::new(random(), 0),
            TxOut::new(
                ExtendedAddr::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                    &PrivateKey::new().unwrap(),
                ))),
                Coin::new(100).unwrap(),
            ),
        ));

        unspent_transactions.push((
            TxoPointer::new(random(), 0),
            TxOut::new(
                ExtendedAddr::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                    &PrivateKey::new().unwrap(),
                ))),
                Coin::new(200).unwrap(),
            ),
        ));

        unspent_transactions.push((
            TxoPointer::new(random(), 0),
            TxOut::new(
                ExtendedAddr::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                    &PrivateKey::new().unwrap(),
                ))),
                Coin::new(300).unwrap(),
            ),
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
    fn check_only_redeem_addresses() {
        let operations = &[Operation::Filter(Filter::OnlyRedeemAddresses)];
        let mut unspent_transactions = sample();
        unspent_transactions.apply_all(operations);
        assert_eq!(3, unspent_transactions.len());
    }

    #[test]
    fn check_only_tree_addresses() {
        let operations = &[Operation::Filter(Filter::OnlyTreeAddresses)];
        let mut unspent_transactions = sample();
        unspent_transactions.apply_all(operations);
        assert_eq!(2, unspent_transactions.len());
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
    fn check_grouped_redeem_first_sort() {
        let operations = &[
            Operation::Group(GroupBy::AddressType(AddressTypeOrder::RedeemAddressFirst)),
            Operation::Sort(Sorter::LowestValueFirst),
        ];
        let mut unspent_transactions = sample();
        unspent_transactions.apply_all(operations);
        assert_eq!(5, unspent_transactions.len());

        assert_eq!(unspent_transactions[0].1.value, Coin::new(100).unwrap());
        assert_eq!(unspent_transactions[1].1.value, Coin::new(200).unwrap());
        assert_eq!(unspent_transactions[2].1.value, Coin::new(300).unwrap());

        assert_eq!(unspent_transactions[3].1.value, Coin::new(150).unwrap());
        assert_eq!(unspent_transactions[4].1.value, Coin::new(250).unwrap());
    }

    #[test]
    fn check_grouped_tree_first_sort() {
        let operations = &[
            Operation::Group(GroupBy::AddressType(AddressTypeOrder::TreeAddressFirst)),
            Operation::Sort(Sorter::LowestValueFirst),
        ];
        let mut unspent_transactions = sample();
        unspent_transactions.apply_all(operations);
        assert_eq!(5, unspent_transactions.len());

        assert_eq!(unspent_transactions[0].1.value, Coin::new(150).unwrap());
        assert_eq!(unspent_transactions[1].1.value, Coin::new(250).unwrap());

        assert_eq!(unspent_transactions[2].1.value, Coin::new(100).unwrap());
        assert_eq!(unspent_transactions[3].1.value, Coin::new(200).unwrap());
        assert_eq!(unspent_transactions[4].1.value, Coin::new(300).unwrap());
    }

    #[test]
    fn check_grouped_tree_first_sort_with_redeem_filter() {
        let operations = &[
            Operation::Group(GroupBy::AddressType(AddressTypeOrder::TreeAddressFirst)),
            Operation::Sort(Sorter::LowestValueFirst),
            Operation::Filter(Filter::OnlyRedeemAddresses),
        ];
        let mut unspent_transactions = sample();
        unspent_transactions.apply_all(operations);
        assert_eq!(3, unspent_transactions.len());

        assert_eq!(unspent_transactions[0].1.value, Coin::new(100).unwrap());
        assert_eq!(unspent_transactions[1].1.value, Coin::new(200).unwrap());
        assert_eq!(unspent_transactions[2].1.value, Coin::new(300).unwrap());
    }
}
