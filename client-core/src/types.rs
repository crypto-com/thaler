//! Types used in `client-core`
pub mod transaction_change;
/// wallet kinds including normal, hd-wallet
pub mod wallet_kind;
#[doc(inline)]
pub use self::transaction_change::{
    BalanceChange, TransactionChange, TransactionInput, TransactionType,
};

pub use self::wallet_kind::WalletKind;
