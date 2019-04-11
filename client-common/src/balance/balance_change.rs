use std::ops::Add;

use failure::ResultExt;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

use chain_core::init::coin::Coin;

use crate::{ErrorKind, Result};

/// Incoming or Outgoing balance change
#[derive(Debug)]
pub enum BalanceChange {
    /// Represents balance addition
    Incoming(Coin),
    /// Represents balance reduction
    Outgoing(Coin),
}

impl Encodable for BalanceChange {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            BalanceChange::Incoming(coin) => s.begin_list(2).append(&0u8).append(coin),
            BalanceChange::Outgoing(coin) => s.begin_list(2).append(&1u8).append(coin),
        };
    }
}

impl Decodable for BalanceChange {
    fn decode(rlp: &Rlp) -> core::result::Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::Custom("Invalid item count"));
        }

        let type_tag: u8 = rlp.val_at(0)?;

        match type_tag {
            0 => Ok(BalanceChange::Incoming(rlp.val_at(1)?)),
            1 => Ok(BalanceChange::Outgoing(rlp.val_at(1)?)),
            _ => Err(DecoderError::Custom("Invalid balance change type")),
        }
    }
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
