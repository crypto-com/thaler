//! Utilities for encryption and decryption
mod abci_transaction_cipher;
pub mod cert;
mod default;
pub mod sgx;

pub use abci_transaction_cipher::MockAbciTransactionObfuscation;
pub use default::DefaultTransactionObfuscation;

use chain_core::tx::data::TxId;
use chain_core::tx::TxAux;
use client_common::{PrivateKey, Result, SignedTransaction, Transaction};

/// Interface for encryption and decryption of transactions
pub trait TransactionObfuscation: Send + Sync {
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
