//! Transaction signing
mod default_signer;
mod dummy_signer;
mod unauthorized_signer;

pub use default_signer::DefaultSigner;
pub use dummy_signer::DummySigner;
pub use unauthorized_signer::UnauthorizedSigner;

use secstr::SecUtf8;

use chain_core::tx::witness::TxWitness;
use client_common::Result;

use crate::SelectedUnspentTransactions;

/// Interface for signing transactions
pub trait Signer: Send + Sync {
    /// Signs given transaction with private keys corresponding to selected unspent transactions
    fn sign<T: AsRef<[u8]>>(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        message: T,
        selected_unspent_transactions: &SelectedUnspentTransactions<'_>,
    ) -> Result<TxWitness>;
}
