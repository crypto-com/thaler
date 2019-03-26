use std::ops::Add;

use crate::balance::BalanceChange;
use crate::Result;

use chain_core::init::coin::Coin;

/// Represents balance change in a transaction
#[derive(Debug)]
pub struct TransactionChange {
    /// ID of transaction which caused this change
    pub transaction_id: String,
    /// Address which is affected by this change
    pub address: String,
    /// Change in balance
    pub balance_change: BalanceChange,
}

impl Add<&TransactionChange> for Coin {
    type Output = Result<Coin>;

    fn add(self, other: &TransactionChange) -> Self::Output {
        self + &other.balance_change
    }
}

impl Add<TransactionChange> for Coin {
    type Output = Result<Coin>;

    fn add(self, other: TransactionChange) -> Self::Output {
        self + &other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_transaction_change(balance_change: BalanceChange) -> TransactionChange {
        TransactionChange {
            transaction_id: Default::default(),
            address: Default::default(),
            balance_change,
        }
    }

    #[test]
    fn add_incoming() {
        let coin = Coin::zero()
            + get_transaction_change(BalanceChange::Incoming(
                Coin::new(30).expect("Unable to create new coin"),
            ));

        assert_eq!(
            Coin::new(30).expect("Unable to create new coin"),
            coin.expect("Unable to add coins"),
            "Coins does not match"
        );
    }

    #[test]
    fn add_incoming_fail() {
        let coin = Coin::max()
            + get_transaction_change(BalanceChange::Incoming(
                Coin::new(30).expect("Unable to create new coin"),
            ));

        assert!(coin.is_err(), "Created coin greater than max value")
    }

    #[test]
    fn add_outgoing() {
        let coin = Coin::new(40).expect("Unable to create new coin")
            + get_transaction_change(BalanceChange::Outgoing(
                Coin::new(30).expect("Unable to create new coin"),
            ));

        assert_eq!(
            Coin::new(10).expect("Unable to create new coin"),
            coin.expect("Unable to add coins"),
            "Coins does not match"
        );
    }

    #[test]
    fn add_outgoing_fail() {
        let coin = Coin::zero()
            + get_transaction_change(BalanceChange::Outgoing(
                Coin::new(30).expect("Unable to create new coin"),
            ));

        assert!(coin.is_err(), "Created negative coin")
    }
}
