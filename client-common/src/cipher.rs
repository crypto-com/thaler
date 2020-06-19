//! Utilities for encryption and decryption
mod default;

#[cfg(feature = "sgx-obfuscation")]
pub mod cert;
pub mod mock;
#[cfg(feature = "sgx-obfuscation")]
pub mod sgx;

pub use default::DefaultTransactionObfuscation;
pub use mock::MockAbciTransactionObfuscation;

use crate::{PrivateKey, Result, SignedTransaction, Transaction};
use chain_core::tx::data::TxId;
use chain_core::tx::TxAux;

/// Interface for encryption and decryption of transactions
pub trait TransactionObfuscation: Send + Sync + Clone {
    /// Retrieves decrypted transactions with given ids. Only transactions of type `Transfer` and `Withdraw` need to be
    /// decrypted.
    fn decrypt(
        &self,
        transaction_ids: &[TxId],
        private_key: &PrivateKey,
    ) -> Result<Vec<Transaction>>;

    /// Encrypts a signed transaction
    fn encrypt(&self, transaction: SignedTransaction) -> Result<TxAux>;
}
