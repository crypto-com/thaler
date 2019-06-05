//! Decorators for unspent transactions
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::output::TxOut;

use crate::unspent_transactions::UnspentTransactionsDecorator;

/// Filters out all the unspent transactions without redeem addresses
pub struct OnlyRedeemAddresses;

impl UnspentTransactionsDecorator for OnlyRedeemAddresses {
    fn decorate(unspent_transactions: &mut Vec<TxOut>) {
        unspent_transactions.retain(|unspent_transaction| match unspent_transaction.address {
            ExtendedAddr::BasicRedeem(_) => true,
            ExtendedAddr::OrTree(_) => false,
        })
    }
}

/// Filters out all the unspent transactions without tree addresses
pub struct OnlyTreeAddresses;

impl UnspentTransactionsDecorator for OnlyTreeAddresses {
    fn decorate(unspent_transactions: &mut Vec<TxOut>) {
        unspent_transactions.retain(|unspent_transaction| match unspent_transaction.address {
            ExtendedAddr::BasicRedeem(_) => false,
            ExtendedAddr::OrTree(_) => true,
        })
    }
}

/// Sorts unspent transactions such that ones with highest value are selected first
pub struct HighestValueFirst;

impl UnspentTransactionsDecorator for HighestValueFirst {
    fn decorate(unspent_transactions: &mut Vec<TxOut>) {
        unspent_transactions.sort_by(|a, b| a.value.cmp(b.value).reverse())
    }
}
