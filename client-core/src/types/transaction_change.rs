//! Types for tracking balance change in a wallet
use std::fmt;
use std::ops::Add;
use std::str::FromStr;

use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use chain_core::{
    init::coin::{Coin, CoinError},
    tx::data::{input::TxoPointer, output::TxOut, TxId},
};
use client_common::tendermint::types::Time;
use client_common::{ErrorKind, Result, ResultExt, Transaction};

/// Wallet balance info
#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct WalletBalance {
    /// The total amount balance
    pub total: Coin,
    /// The available amount balance that can be currently used
    pub available: Coin,
    /// The pending amount balance
    pub pending: Coin,
}

/// Transaction pending infomation
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct TransactionPending {
    /// The selected inputs of the transaction
    pub used_inputs: Vec<TxoPointer>,
    /// The block height when broadcast the transaction
    pub block_height: u64,
    /// the return amount of the transaction
    pub return_amount: Coin,
}

/// Transaction data with attached metadata
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionChange {
    /// Transaction ID
    #[serde(serialize_with = "serialize_transaction_id")]
    #[serde(deserialize_with = "deserialize_transaction_id")]
    pub transaction_id: TxId,
    /// Transaction inputs
    pub inputs: Vec<TransactionInput>,
    /// Transaction outputs
    pub outputs: Vec<TxOut>,
    /// Balance change caused by transaction
    #[serde(flatten)]
    pub balance_change: BalanceChange,
    /// Transaction type
    pub transaction_type: TransactionType,
    /// Height of block which has this transaction
    pub block_height: u64,
    /// Time of block which has this transaction
    pub block_time: Time,
}

/// Transaction input
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct TransactionInput {
    /// Pointer to unspent transaction
    #[serde(flatten)]
    pub pointer: TxoPointer,
    /// Details of unspent transaction (if available)
    pub output: Option<TxOut>,
}

/// Type of transaction
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub enum TransactionType {
    /// Transfer transaction
    Transfer,
    /// Withdraw transaction
    Withdraw,
    /// Unbond transaction
    Unbond,
    /// Deposit transaction
    Deposit,
}

impl fmt::Display for TransactionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionType::Transfer => write!(f, "Transfer"),
            TransactionType::Withdraw => write!(f, "Withdraw"),
            TransactionType::Unbond => write!(f, "Unbond"),
            TransactionType::Deposit => write!(f, "Deposit"),
        }
    }
}

/// Balance change a transaction has caused
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Encode, Decode)]
#[serde(tag = "kind")]
pub enum BalanceChange {
    /// Incoming value. Represents balance addition.
    Incoming {
        /// Value of incoming balance change
        value: Coin,
    },
    /// Outgoing value and fee. Represents balance reduction.
    Outgoing {
        /// Value of outgoing balance change
        value: Coin,
        /// Fee paid for transaction with outgoing amount
        fee: Coin,
    },
    /// No change in balance
    NoChange,
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

impl Encode for TransactionChange {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.transaction_id.encode_to(dest);
        self.inputs.encode_to(dest);
        self.outputs.encode_to(dest);
        self.balance_change.encode_to(dest);
        self.transaction_type.encode_to(dest);
        self.block_height.encode_to(dest);
        self.block_time.to_rfc3339().encode_to(dest);
    }

    fn size_hint(&self) -> usize {
        self.transaction_id.size_hint()
            + self.inputs.size_hint()
            + self.outputs.size_hint()
            + self.balance_change.size_hint()
            + self.block_height.size_hint()
            + self.block_time.to_rfc3339().as_bytes().size_hint()
    }
}

impl Decode for TransactionChange {
    fn decode<I: Input>(input: &mut I) -> std::result::Result<Self, Error> {
        let transaction_id = TxId::decode(input)?;
        let inputs = <Vec<TransactionInput>>::decode(input)?;
        let outputs = <Vec<TxOut>>::decode(input)?;
        let balance_change = BalanceChange::decode(input)?;
        let transaction_type = TransactionType::decode(input)?;
        let block_height = u64::decode(input)?;
        let block_time = Time::from_str(&String::decode(input)?)
            .map_err(|_| Error::from("Unable to parse block time"))?;
        Ok(TransactionChange {
            transaction_id,
            inputs,
            outputs,
            balance_change,
            transaction_type,
            block_height,
            block_time,
        })
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add<BalanceChange> for Coin {
    type Output = Result<Coin>;

    fn add(self, other: BalanceChange) -> Self::Output {
        match other {
            BalanceChange::Incoming { value } => {
                let new_value: std::result::Result<Coin, CoinError> = self + value;
                new_value.chain(|| {
                    (
                        ErrorKind::IllegalInput,
                        "Balance exceeded maximum value while adding",
                    )
                })
            }
            BalanceChange::Outgoing { value, fee } => {
                let new_value = (self - value).chain(|| {
                    (
                        ErrorKind::IllegalInput,
                        "Balance became negative while adding",
                    )
                })?;

                (new_value - fee).chain(|| {
                    (
                        ErrorKind::IllegalInput,
                        "Balance became negative while adding",
                    )
                })
            }
            BalanceChange::NoChange => Ok(self),
        }
    }
}

impl From<&Transaction> for TransactionType {
    fn from(transaction: &Transaction) -> TransactionType {
        match transaction {
            Transaction::TransferTransaction(_) => TransactionType::Transfer,
            Transaction::WithdrawUnbondedStakeTransaction(_) => TransactionType::Withdraw,
            Transaction::UnbondStakeTransaction(_) => TransactionType::Unbond,
            Transaction::DepositStakeTransaction(_) => TransactionType::Deposit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_core::{init::coin::Coin, tx::data::txid_hash};

    #[test]
    fn check_transaction_change_encode_decode() {
        let transaction_change = TransactionChange {
            transaction_id: txid_hash(&[0, 1, 2]),
            inputs: Vec::new(),
            outputs: Vec::new(),
            balance_change: BalanceChange::Incoming {
                value: Coin::zero(),
            },
            transaction_type: TransactionType::Transfer,
            block_height: 0,
            block_time: Time::now(),
        };

        let encoded = transaction_change.encode();
        let decoded = TransactionChange::decode(&mut encoded.as_ref()).unwrap();

        assert_eq!(transaction_change, decoded);
    }

    #[test]
    fn balance_change_add_incoming() {
        let coin = Coin::zero()
            + BalanceChange::Incoming {
                value: Coin::new(30).expect("Unable to create new coin"),
            };

        assert_eq!(
            Coin::new(30).expect("Unable to create new coin"),
            coin.expect("Unable to add coins"),
            "Coins does not match"
        );
    }

    #[test]
    fn balance_change_add_incoming_fail() {
        let coin = Coin::max()
            + BalanceChange::Incoming {
                value: Coin::new(30).expect("Unable to create new coin"),
            };

        assert!(coin.is_err(), "Created coin greater than max value")
    }

    #[test]
    fn balance_change_add_outgoing() {
        let coin = Coin::new(40).expect("Unable to create new coin")
            + BalanceChange::Outgoing {
                value: Coin::new(25).expect("Unable to create new coin"),
                fee: Coin::new(5).expect("Unable to create new coin"),
            };

        assert_eq!(
            Coin::new(10).expect("Unable to create new coin"),
            coin.expect("Unable to add coins"),
            "Coins does not match"
        );
    }

    #[test]
    fn balance_change_add_outgoing_fail() {
        let coin = Coin::zero()
            + BalanceChange::Outgoing {
                value: Coin::new(25).expect("Unable to create new coin"),
                fee: Coin::new(5).expect("Unable to create new coin"),
            };

        assert!(coin.is_err(), "Created negative coin")
    }
}
