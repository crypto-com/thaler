use std::ops::Add;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::TxId;

use crate::balance::BalanceChange;
use crate::Result;

/// Represents balance change in a transaction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionChange {
    /// ID of transaction which caused this change
    #[serde(serialize_with = "serialize_transaction_id")]
    #[serde(deserialize_with = "deserialize_transaction_id")]
    pub transaction_id: TxId,
    /// Address which is affected by this change
    #[serde(serialize_with = "serialize_address")]
    #[serde(deserialize_with = "deserialize_address")]
    pub address: ExtendedAddr,
    /// Change in balance
    #[serde(flatten)]
    pub balance_change: BalanceChange,
    /// Height of block which has this transaction
    pub block_height: u64,
    /// Time of block which has this transaction
    pub block_time: DateTime<Utc>,
}

fn serialize_transaction_id<S>(
    transaction_id: &TxId,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(transaction_id))
}

fn deserialize_transaction_id<'de, D>(deserializer: D) -> std::result::Result<TxId, D::Error>
where
    D: Deserializer<'de>,
{
    let transaction_id_raw: &str = Deserialize::deserialize(deserializer)?;
    let transaction_id_vec =
        hex::decode(transaction_id_raw).map_err(|e| de::Error::custom(e.to_string()))?;
    if transaction_id_vec.len() != 32 {
        return Err(de::Error::custom("Invalid transaction id length"));
    }

    let mut transaction_id = [0; 32];
    transaction_id.copy_from_slice(&transaction_id_vec);

    Ok(transaction_id)
}

fn serialize_address<S>(
    address: &ExtendedAddr,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&address.to_string())
}

fn deserialize_address<'de, D>(deserializer: D) -> std::result::Result<ExtendedAddr, D::Error>
where
    D: Deserializer<'de>,
{
    let address_raw: &str = Deserialize::deserialize(deserializer)?;
    ExtendedAddr::from_str(address_raw).map_err(|e| de::Error::custom(e.to_string()))
}

impl Encode for TransactionChange {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.transaction_id.encode_to(dest);
        self.address.encode_to(dest);
        self.balance_change.encode_to(dest);
        self.block_height.encode_to(dest);
        self.block_time.to_rfc3339().encode_to(dest);
    }

    fn size_hint(&self) -> usize {
        self.transaction_id.size_hint()
            + self.address.size_hint()
            + self.balance_change.size_hint()
            + self.block_height.size_hint()
            + self.block_time.to_rfc3339().as_bytes().size_hint()
    }
}

impl Decode for TransactionChange {
    fn decode<I: Input>(input: &mut I) -> std::result::Result<Self, Error> {
        let transaction_id = TxId::decode(input)?;
        let address = ExtendedAddr::decode(input)?;
        let balance_change = BalanceChange::decode(input)?;
        let block_height = u64::decode(input)?;
        let block_time = DateTime::from_str(&String::decode(input)?)
            .map_err(|_| Error::from("Unable to parse block time"))?;
        Ok(TransactionChange {
            transaction_id,
            address,
            balance_change,
            block_height,
            block_time,
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
            block_height: 0,
            block_time: DateTime::from(SystemTime::now()),
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
