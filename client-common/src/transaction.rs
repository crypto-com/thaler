use parity_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use chain_core::state::account::{DepositBondTx, UnbondTx, WithdrawUnbondedTx};
use chain_core::tx::data::{Tx, TxId};
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
