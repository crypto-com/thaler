//! Types used in `client-core`
pub mod transaction_change;

#[doc(inline)]
pub use self::transaction_change::{
    BalanceChange, TransactionChange, TransactionInput, TransactionType,
};
