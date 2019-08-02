use std::ops::Add;

use chain_core::init::coin::Coin;
use failure::ResultExt;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{ErrorKind, Result};

/// Incoming or Outgoing balance change
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub enum BalanceChange {
    /// Represents balance addition
    Incoming(Coin),
    /// Represents balance reduction
    Outgoing(Coin),
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add<&BalanceChange> for Coin {
    type Output = Result<Coin>;

    fn add(self, other: &BalanceChange) -> Self::Output {
        match other {
            BalanceChange::Incoming(change) => {
                Ok((self + change).context(ErrorKind::BalanceAdditionError)?)
            }
            BalanceChange::Outgoing(change) => {
                Ok((self - change).context(ErrorKind::BalanceAdditionError)?)
            }
        }
    }
}

impl Add<BalanceChange> for Coin {
    type Output = Result<Coin>;

    fn add(self, other: BalanceChange) -> Self::Output {
        self + &other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_incoming() {
        let coin = Coin::zero()
            + BalanceChange::Incoming(Coin::new(30).expect("Unable to create new coin"));

        assert_eq!(
            Coin::new(30).expect("Unable to create new coin"),
            coin.expect("Unable to add coins"),
            "Coins does not match"
        );
    }

    #[test]
    fn add_incoming_fail() {
        let coin = Coin::max()
            + BalanceChange::Incoming(Coin::new(30).expect("Unable to create new coin"));

        assert!(coin.is_err(), "Created coin greater than max value")
    }

    #[test]
    fn add_outgoing() {
        let coin = Coin::new(40).expect("Unable to create new coin")
            + BalanceChange::Outgoing(Coin::new(30).expect("Unable to create new coin"));

        assert_eq!(
            Coin::new(10).expect("Unable to create new coin"),
            coin.expect("Unable to add coins"),
            "Coins does not match"
        );
    }

    #[test]
    fn add_outgoing_fail() {
        let coin = Coin::zero()
            + BalanceChange::Outgoing(Coin::new(30).expect("Unable to create new coin"));

        assert!(coin.is_err(), "Created negative coin")
    }

}
