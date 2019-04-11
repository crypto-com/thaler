use std::ops::Add;

use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

use crate::balance::BalanceChange;
use crate::Result;

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::TxId;

/// Represents balance change in a transaction
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionChange {
    /// ID of transaction which caused this change
    pub transaction_id: TxId,
    /// Address which is affected by this change
    pub address: ExtendedAddr,
    /// Change in balance
    pub balance_change: BalanceChange,
}

impl Encodable for TransactionChange {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append(&self.transaction_id)
            .append(&self.address)
            .append(&self.balance_change);
    }
}

impl Decodable for TransactionChange {
    fn decode(rlp: &Rlp) -> core::result::Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::Custom("Invalid item count"));
        }

        Ok(TransactionChange {
            transaction_id: rlp.val_at(0)?,
            address: rlp.val_at(1)?,
            balance_change: rlp.val_at(2)?,
        })
    }
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

    use rlp::{decode, encode};

    use chain_core::tx::data::txid_hash;

    fn get_transaction_change(balance_change: BalanceChange) -> TransactionChange {
        TransactionChange {
            transaction_id: txid_hash(&[0, 1, 2]),
            address: ExtendedAddr::BasicRedeem(Default::default()),
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

    #[test]
    fn check_encoding() {
        let change = get_transaction_change(BalanceChange::Incoming(
            Coin::new(32).expect("Unable to create new coin"),
        ));
        let new_change = decode(&encode(&change)).expect("Unable to decode transaction change");

        assert_eq!(change, new_change, "Incorrect transaction change encoding");
    }
}
