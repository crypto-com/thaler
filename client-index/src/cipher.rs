//! Utilities for encryption and decryption
mod abci_transaction_cipher;

pub use abci_transaction_cipher::AbciTransactionCipher;

use chain_core::tx::data::TxId;
use chain_core::tx::TxAux;
use client_common::{PrivateKey, Result, SignedTransaction, Transaction};

/// Interface for encryption and decryption of transactions
pub trait TransactionCipher: Send + Sync {
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
