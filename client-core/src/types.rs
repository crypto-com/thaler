//! Types used in `client-core`
mod address_type;
mod wallet_type;

pub mod transaction_change;

pub use self::address_type::AddressType;
#[doc(inline)]
pub use self::transaction_change::{
    BalanceChange, TransactionChange, TransactionInput, TransactionPending, TransactionType,
    WalletBalance,
};
pub use self::wallet_type::WalletKind;
