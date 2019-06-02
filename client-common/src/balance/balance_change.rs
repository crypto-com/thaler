use std::ops::Add;

use chain_core::init::coin::Coin;
use failure::ResultExt;
use parity_codec::{Decode, Encode};
// use serde::ser::{Serialize, SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};

use crate::serializable::SerializableCoin;
use crate::{ErrorKind, Result};

/// Incoming or Outgoing balance change
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub enum BalanceChange {
    /// Represents balance addition
    Incoming(SerializableCoin),
    /// Represents balance reduction
    Outgoing(SerializableCoin),
}

// TODO: Remove old custom serializer
// impl Serialize for BalanceChange {
//     fn serialize<S>(&self, serializer: S) -> CoreResult<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let mut state = serializer.serialize_struct("BalanceChange", 1)?;
//         match &self {
//             BalanceChange::Incoming(coin) => {
//                 state.serialize_field("Incoming", &String::from(*coin))?
//             }
//             BalanceChange::Outgoing(coin) => {
//                 state.serialize_field("Outgoing", &String::from(*coin))?
//             }
//         };

//         state.end()
//     }
// }

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add<&BalanceChange> for Coin {
    type Output = Result<Coin>;

    fn add(self, other: &BalanceChange) -> Self::Output {
        match other {
            BalanceChange::Incoming(change) => {
                Ok((self + change.inner()).context(ErrorKind::BalanceAdditionError)?)
            }
            BalanceChange::Outgoing(change) => {
                Ok((self - change.inner()).context(ErrorKind::BalanceAdditionError)?)
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
            + BalanceChange::Incoming(SerializableCoin(Coin::new(30).expect("Unable to create new coin")));

        assert_eq!(
            Coin::new(30).expect("Unable to create new coin"),
            coin.expect("Unable to add coins"),
            "Coins does not match"
        );
    }

    #[test]
    fn add_incoming_fail() {
        let coin = Coin::max()
            + BalanceChange::Incoming(SerializableCoin(Coin::new(30).expect("Unable to create new coin")));

        assert!(coin.is_err(), "Created coin greater than max value")
    }

    #[test]
    fn add_outgoing() {
        let coin = Coin::new(40).expect("Unable to create new coin")
            + BalanceChange::Outgoing(SerializableCoin(Coin::new(30).expect("Unable to create new coin")));

        assert_eq!(
            Coin::new(10).expect("Unable to create new coin"),
            coin.expect("Unable to add coins"),
            "Coins does not match"
        );
    }

    #[test]
    fn add_outgoing_fail() {
        let coin = Coin::zero()
            + BalanceChange::Outgoing(SerializableCoin(Coin::new(30).expect("Unable to create new coin")));

        assert!(coin.is_err(), "Created negative coin")
    }

    mod serializer_deserializer_test {
        use super::*;
        use serde_json;

        #[test]
        fn test_serialize_should_return_coin_amount_in_numeric_string() {
            let balance_change =
                BalanceChange::Incoming(SerializableCoin(Coin::new(99999).expect("Unable to create new coin")));
            let actual_json =
                serde_json::to_string(&balance_change).expect("Unable to serialize BalanceChange");

            assert_eq!(actual_json, r#"{"Incoming":"99999"}"#)
        }

        #[test]
        fn test_serialize_incoming_balance_change_should_work() {
            let balance_change =
                BalanceChange::Incoming(SerializableCoin(Coin::new(30).expect("Unable to create new coin")));
            let actual_json =
                serde_json::to_string(&balance_change).expect("Unable to serialize BalanceChange");

            assert_eq!(actual_json, r#"{"Incoming":"30"}"#)
        }

        #[test]
        fn test_serialize_outgoing_balance_change_should_work() {
            let balance_change =
                BalanceChange::Outgoing(SerializableCoin(Coin::new(30).expect("Unable to create new coin")));
            let actual_json =
                serde_json::to_string(&balance_change).expect("Unable to serialize BalanceChange");

            assert_eq!(actual_json, r#"{"Outgoing":"30"}"#)
        }

        #[test]
        fn test_serialize_large_amount_should_work() {
            let balance_change = BalanceChange::Incoming(
                SerializableCoin(Coin::new(10000000000000000000).expect("Unable to create new coin")),
            );
            let actual_json =
                serde_json::to_string(&balance_change).expect("Unable to serialize BalanceChange");

            assert_eq!(actual_json, r#"{"Incoming":"10000000000000000000"}"#)
        }
    }
}
