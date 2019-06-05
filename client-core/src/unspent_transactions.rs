//! Operations on unspent transactions
use std::ops::{Deref, DerefMut};

use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;

/// An iterator over unspent transactions
///
/// # Usage
///
/// ```no_run
/// # use chain_core::tx::data::input::TxoPointer;
/// # use chain_core::tx::data::output::TxOut;
/// # use client_core::unspent_transactions::{UnspentTransactions, Decorator::*};
/// # use client_core::wallet::DefaultWalletClient;
/// // Retrieve a list of unspent transactions from an external source
/// let unspent_transactions: Vec<(TxoPointer, TxOut)> = Vec::new();
///
/// // Resolve these unspent transactions into `TxOut`
/// let mut unspent_transactions = UnspentTransactions::new(unspent_transactions);
///
/// // This will filter and sort unspent transactions: only transactions with
/// // redeem addresses and in decreasing order of their value.
/// unspent_transactions
///     .decorate_with(OnlyRedeemAddresses)
///     .decorate_with(HighestValueFirst);
/// ```
#[derive(Debug)]
pub struct UnspentTransactions {
    inner: Vec<(TxoPointer, TxOut)>,
}

impl Deref for UnspentTransactions {
    type Target = Vec<(TxoPointer, TxOut)>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for UnspentTransactions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl UnspentTransactions {
    /// Creates a new instance of unspent transactions
    pub fn new(unspent_transactions: Vec<(TxoPointer, TxOut)>) -> Self {
        Self {
            inner: unspent_transactions,
        }
    }

    /// Decorates unspent transactions with a decorator
    pub fn decorate_with(&mut self, decorator: Decorator) -> &mut Self {
        decorator.decorate(self);
        self.shrink_to_fit();
        self
    }

    /// Decorates unspent transactions with a list of decorators
    pub fn decorate_with_all(&mut self, decorators: &[Decorator]) -> &mut Self {
        for decorator in decorators {
            decorator.decorate(self);
        }
        self.shrink_to_fit();
        self
    }

    /// Returns inner vector of unspent transactions
    pub fn unwrap(self) -> Vec<(TxoPointer, TxOut)> {
        self.inner
    }
}

/// Decorators for unspent transactions
pub enum Decorator {
    /// Filters out all the unspent transactions without redeem addresses
    OnlyRedeemAddresses,
    /// Filters out all the unspent transactions without tree addresses
    OnlyTreeAddresses,
    /// Sorts unspent transactions such that ones with highest value are selected first
    HighestValueFirst,
}

impl Decorator {
    /// Decorates unspent transactions
    fn decorate(&self, unspent_transactions: &mut UnspentTransactions) {
        use Decorator::*;

        match self {
            OnlyRedeemAddresses => unspent_transactions.retain(|(_, unspent_transaction)| {
                match unspent_transaction.address {
                    ExtendedAddr::BasicRedeem(_) => true,
                    ExtendedAddr::OrTree(_) => false,
                }
            }),
            OnlyTreeAddresses => unspent_transactions.retain(|(_, unspent_transaction)| {
                match unspent_transaction.address {
                    ExtendedAddr::BasicRedeem(_) => false,
                    ExtendedAddr::OrTree(_) => true,
                }
            }),
            HighestValueFirst => {
                unspent_transactions
                    .sort_by_key(|(_, unspent_transaction)| unspent_transaction.value);
                unspent_transactions.reverse();
            }
        }
    }
}
