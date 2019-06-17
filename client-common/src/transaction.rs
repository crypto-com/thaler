use parity_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use chain_core::state::account::{DepositBondTx, UnbondTx, WithdrawUnbondedTx};
use chain_core::tx::data::Tx;

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
