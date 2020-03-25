//! Transaction signing
mod dummy_signer;
mod key_pair_signer;
mod unauthorized_signer;
mod wallet_signer;

pub use dummy_signer::DummySigner;
pub use key_pair_signer::KeyPairSigner;
pub use unauthorized_signer::UnauthorizedSigner;
pub use wallet_signer::{WalletSigner, WalletSignerManager};

use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use client_common::{Result, Transaction};

use crate::SelectedUnspentTransactions;

/// Interface for signing message and transactions
pub trait Signer: Send + Sync {
    /// Signs given transaction with private keys corresponding to selected
    /// unspent transactions
    fn schnorr_sign_transaction(
        &self,
        tx: &Transaction,
        selected_unspent_transactions: &SelectedUnspentTransactions<'_>,
    ) -> Result<TxWitness>;

    /// Returns the sign condition of an address to the signer
    fn schnorr_sign_condition(&self, signing_addr: &ExtendedAddr) -> Result<SignCondition>;

    /// Sign given message with private key corresponding to provided address
    /// using schnorr signature
    fn schnorr_sign<'a>(
        &self,
        tx: &Transaction,
        signing_addr: &'a ExtendedAddr,
    ) -> Result<TxInWitness>;
}

/// Signing condition of an address to the signer
// TODO: Add MultiSigUnlock condition
#[derive(PartialEq)]
pub enum SignCondition {
    /// can unlock outputs under the address on its own
    SingleSignUnlock,
    /// cannot unlock outputs under the address
    Impossible,
}
