use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::{ErrorKind, Result, ResultExt};
use chain_core::state::account::{
    DepositBondTx, StakedStateOpWitness, UnbondTx, UnjailTx, WithdrawUnbondedTx,
};
use chain_core::state::validator::NodeJoinRequestTx;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::witness::TxWitness;
use chain_core::tx::TransactionId;

/// A struct which the sender can download and the receiver can import
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct TransactionInfo {
    /// enum Transaction type
    pub tx: Transaction,
    /// block height when the tx broadcast
    pub block_height: u64,
}

impl TransactionInfo {
    /// encode with serde_json and base64
    pub fn encode(&self) -> Result<String> {
        let s1 = serde_json::to_string(self).chain(|| {
            (
                ErrorKind::EncryptionError,
                "Unable to encrypt transaction info",
            )
        })?;
        let s2 = base64::encode(&s1);
        Ok(s2)
    }

    /// decoded from a string
    pub fn decode(tx_str: &str) -> Result<Self> {
        base64::decode(tx_str)
            .map(|raw| {
                serde_json::from_slice(&raw).chain(|| {
                    (
                        ErrorKind::DecryptionError,
                        "Unable to decrypt transaction info",
                    )
                })
            })
            .chain(|| {
                (
                    ErrorKind::DecryptionError,
                    "Unable to decrypt transaction info",
                )
            })?
    }
}

/// Enum containing different types of transactions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
#[serde(tag = "type")]
pub enum Transaction {
    /// Transfer transaction
    TransferTransaction(Tx),
    /// Deposit stake transaction
    DepositStakeTransaction(DepositBondTx),
    /// Unbound stake transaction
    UnbondStakeTransaction(UnbondTx),
    /// Withdraw unbounded stake transaction
    WithdrawUnbondedStakeTransaction(WithdrawUnbondedTx),
    /// Unjail transaction
    UnjailTransaction(UnjailTx),
    /// Node join transaction
    NodejoinTransaction(NodeJoinRequestTx),
}

impl Transaction {
    /// Returns inputs of transaction
    pub fn inputs(&self) -> &[TxoPointer] {
        match self {
            Transaction::TransferTransaction(ref transaction) => &transaction.inputs,
            Transaction::DepositStakeTransaction(ref transaction) => &transaction.inputs,
            Transaction::UnbondStakeTransaction(_)
            | Transaction::WithdrawUnbondedStakeTransaction(_)
            | Transaction::UnjailTransaction(_)
            | Transaction::NodejoinTransaction(_) => &[],
        }
    }

    /// Returns outputs of transaction
    pub fn outputs(&self) -> &[TxOut] {
        match self {
            Transaction::TransferTransaction(ref transaction) => &transaction.outputs,
            Transaction::WithdrawUnbondedStakeTransaction(ref transaction) => &transaction.outputs,
            Transaction::UnbondStakeTransaction(_)
            | Transaction::DepositStakeTransaction(_)
            | Transaction::UnjailTransaction(_)
            | Transaction::NodejoinTransaction(_) => &[],
        }
    }
}

impl TransactionId for Transaction {
    fn id(&self) -> TxId {
        match self {
            Transaction::TransferTransaction(ref transaction) => transaction.id(),
            Transaction::DepositStakeTransaction(ref transaction) => transaction.id(),
            Transaction::UnbondStakeTransaction(ref transaction) => transaction.id(),
            Transaction::WithdrawUnbondedStakeTransaction(ref transaction) => transaction.id(),
            Transaction::UnjailTransaction(ref transaction) => transaction.id(),
            Transaction::NodejoinTransaction(ref transaction) => transaction.id(),
        }
    }
}

/// Enum representing a signed transaction
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum SignedTransaction {
    /// Transfer transaction
    TransferTransaction(Tx, TxWitness),
    /// Deposit stake transaction
    DepositStakeTransaction(DepositBondTx, TxWitness),
    /// Withdraw unbounded stake transaction
    WithdrawUnbondedStakeTransaction(WithdrawUnbondedTx, StakedStateOpWitness),
}

impl TransactionId for SignedTransaction {
    fn id(&self) -> TxId {
        match self {
            SignedTransaction::TransferTransaction(ref transaction, _) => transaction.id(),
            SignedTransaction::DepositStakeTransaction(ref transaction, _) => transaction.id(),
            SignedTransaction::WithdrawUnbondedStakeTransaction(ref transaction, _) => {
                transaction.id()
            }
        }
    }
}
