use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use chain_core::state::account::{
    DepositBondTx, StakedState, StakedStateOpWitness, UnbondTx, WithdrawUnbondedTx,
};
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::witness::TxWitness;
use chain_core::tx::TransactionId;

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
}

impl TransactionId for Transaction {
    fn id(&self) -> TxId {
        match self {
            Transaction::TransferTransaction(ref transaction) => transaction.id(),
            Transaction::DepositStakeTransaction(ref transaction) => transaction.id(),
            Transaction::UnbondStakeTransaction(ref transaction) => transaction.id(),
            Transaction::WithdrawUnbondedStakeTransaction(ref transaction) => transaction.id(),
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
    /// Unbound stake transaction
    UnbondStakeTransaction(UnbondTx, StakedStateOpWitness),
    /// Withdraw unbounded stake transaction
    ///
    /// NOTE: `StakedState` is needed because this type is primarily for encryption of transaction where we need
    /// `StakedState`.
    WithdrawUnbondedStakeTransaction(WithdrawUnbondedTx, StakedState, StakedStateOpWitness),
}

impl TransactionId for SignedTransaction {
    fn id(&self) -> TxId {
        match self {
            SignedTransaction::TransferTransaction(ref transaction, _) => transaction.id(),
            SignedTransaction::DepositStakeTransaction(ref transaction, _) => transaction.id(),
            SignedTransaction::UnbondStakeTransaction(ref transaction, _) => transaction.id(),
            SignedTransaction::WithdrawUnbondedStakeTransaction(ref transaction, _, _) => {
                transaction.id()
            }
        }
    }
}
