use parity_codec::{Decode, Encode};
use serde::de::{Deserialize, Deserializer, Error, Visitor};
use serde::{Serialize, Serializer};
use std::convert::From;
use std::fmt;

use chain_core::init::coin::{Coin, CoinError};

/// Coin wrapper that support serialize to and deserialize from string
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct SerializableCoin(pub Coin);

impl SerializableCoin {
    /// Returns the inner Coin
    pub fn inner(&self) -> Coin {
        self.0.clone()
    }
}

impl fmt::Display for SerializableCoin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for SerializableCoin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&String::from(self.0))
    }
}

impl<'de> Deserialize<'de> for SerializableCoin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrVisitor;

        impl<'de> Visitor<'de> for StrVisitor {
            type Value = SerializableCoin;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .write_str("the coin amount in the range (0..total supply) as numeric string")
            }

            #[inline]
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let amount: u64 = value
                    .parse()
                    .map_err(|_| E::custom("coin amount is not a valid numeric string"))?;

                let coin = Coin::new(amount).map_err(|err| E::custom(format!("{}", err)))?;

                Ok(SerializableCoin(coin))
            }
        }

        deserializer.deserialize_str(StrVisitor)
    }
}

impl ::std::str::FromStr for SerializableCoin {
    type Err = CoinError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let coin = s.parse::<Coin>()?;

        Ok(SerializableCoin(coin))
    }
}

impl From<SerializableCoin> for Coin {
    fn from(item: SerializableCoin) -> Coin {
        item.inner()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_inner_should_return_coin() {
        let coin = Coin::new(10000000000000000000).expect("Unable to create new coin");
        let serializable_coin = SerializableCoin(coin.clone());

        assert_eq!(serializable_coin.inner(), coin);
    }

    #[test]
    fn test_from_str_into_serializable_coin() {
        let amount_str = "10000000000000000000";

        assert!(amount_str.parse::<SerializableCoin>().is_ok());
    }

    #[test]
    fn test_serializable_coin_into_coin() {
        let coin = Coin::new(10000000000000000000).expect("Unable to create new coin");
        let serializable_coin = SerializableCoin(coin.clone());

        let actual_coin: Coin = serializable_coin.into();

        assert_eq!(actual_coin, coin);
    }

    mod serializer_deserializer_test {
        use super::*;
        use serde_json;

        #[test]
        fn test_serialize_to_string() {
            let coin = Coin::new(10000000000000000000).expect("Unable to create new coin");
            let serializable_coin = SerializableCoin(coin);

            let json = serde_json::to_string(&serializable_coin)
                .expect("Unable to serialize SerializableCoin");
            assert_eq!(json, "\"10000000000000000000\"");
        }

        #[test]
        fn test_deserialize_from_number_should_give_error() {
            let deserialize_result = serde_json::from_str::<SerializableCoin>("99999");

            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_empty_string_should_give_error() {
            let deserialize_result = serde_json::from_str::<SerializableCoin>("\"\"");

            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_out_of_range_should_give_error() {
            let deserialize_result =
                serde_json::from_str::<SerializableCoin>("\"10000000000000000001\"");

            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_negative_should_give_error() {
            let deserialize_result = serde_json::from_str::<SerializableCoin>("\"-1\"");

            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_hexadecimal_should_give_error() {
            let deserialize_result = serde_json::from_str::<SerializableCoin>("\"0xAB\"");
            assert!(deserialize_result.is_err());

            let deserialize_result = serde_json::from_str::<SerializableCoin>("\"AB\"");
            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_non_number_should_give_error() {
            let deserialize_result = serde_json::from_str::<SerializableCoin>("\"Crypto.com\"");

            assert!(deserialize_result.is_err());
        }

        #[test]
        fn test_deserialize_from_plus_prefix_should_work() {
            let deserialize_result = serde_json::from_str::<SerializableCoin>("\"+99999\"");

            assert_eq!(
                deserialize_result.expect("Unable to deserialize to SerializableCoin"),
                SerializableCoin(Coin::new(99999).expect("Unable to create new coin"))
            );
        }

        #[test]
        fn test_deserialize_from_string_should_work() {
            let deserialize_result = serde_json::from_str::<SerializableCoin>("\"99999\"");

            assert_eq!(
                deserialize_result.expect("Unable to deserialize to SerializableCoin"),
                SerializableCoin(Coin::new(99999).expect("Unable to create new coin"))
            );
        }

        #[test]
        fn test_deserialize_from_large_amount_should_work() {
            let deserialize_result =
                serde_json::from_str::<SerializableCoin>("\"10000000000000000000\"");

            assert_eq!(
                deserialize_result.expect("Unable to deserialize to SerializableCoin"),
                SerializableCoin(
                    Coin::new(10000000000000000000).expect("Unable to create new coin")
                )
            );
        }
    }
}
