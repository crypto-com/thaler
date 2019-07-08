use std::ops::Add;
use std::str::FromStr;

use chrono::offset::Utc;
use chrono::DateTime;
use parity_codec::{Decode, Encode, Input, Output};
use serde::{Deserialize, Serialize};

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::TxId;

use crate::balance::BalanceChange;
use crate::Result;

/// Represents balance change in a transaction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionChange {
    /// ID of transaction which caused this change
    pub transaction_id: TxId,
    /// Address which is affected by this change
    pub address: ExtendedAddr,
    /// Change in balance
    pub balance_change: BalanceChange,
    /// Height of block which has this transaction
    pub height: u64,
    /// Time of block which has this transaction
    pub time: DateTime<Utc>,
}

impl Encode for TransactionChange {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.transaction_id.encode_to(dest);
        self.address.encode_to(dest);
        self.balance_change.encode_to(dest);
        self.height.encode_to(dest);
        self.time.to_rfc3339().encode_to(dest);
    }
}

impl Decode for TransactionChange {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let transaction_id = TxId::decode(input)?;
        let address = ExtendedAddr::decode(input)?;
        let balance_change = BalanceChange::decode(input)?;
        let height = u64::decode(input)?;
        let time = DateTime::from_str(&String::decode(input)?).ok()?;
        Some(TransactionChange {
            transaction_id,
            address,
            balance_change,
            height,
            time,
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

    use std::time::SystemTime;

    use chain_core::tx::data::txid_hash;

    fn get_transaction_change(balance_change: BalanceChange) -> TransactionChange {
        TransactionChange {
            transaction_id: txid_hash(&[0, 1, 2]),
            address: ExtendedAddr::OrTree(Default::default()),
            balance_change,
            height: 0,
            time: DateTime::from(SystemTime::now()),
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
