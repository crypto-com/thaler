//! Transaction builder
mod default_wallet_transaction_builder;
mod raw_transfer_transaction_builder;
mod unauthorized_wallet_transaction_builder;

pub use default_wallet_transaction_builder::DefaultWalletTransactionBuilder;
pub use raw_transfer_transaction_builder::RawTransferTransactionBuilder;
pub use unauthorized_wallet_transaction_builder::UnauthorizedWalletTransactionBuilder;

use secstr::SecUtf8;

use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::{PrivateKey, Result, SignedTransaction, Transaction};

use crate::UnspentTransactions;
use chain_core::tx::data::TxId;

/// Interface for wallet transaction building from output addresses and amount.
/// This trait is also responsible for UTXO selection.
pub trait WalletTransactionBuilder: Send + Sync {
    /// Builds a transfer transaction
    ///
    /// # Attributes
    ///
    /// - `name`: Name of wallet
    /// - `passphrase`: Passphrase of wallet
    /// - `unspent_transactions`: Unspent transactions
    /// - `outputs`: Transaction outputs
    /// - `return_address`: Address to which change amount will get returned
    /// - `attributes`: Transaction attributes,
    fn build_transfer_tx(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        unspent_transactions: UnspentTransactions,
        outputs: Vec<TxOut>,
        return_address: ExtendedAddr,
        attributes: TxAttributes,
    ) -> Result<TxAux>;

    /// Obfuscates given signed transaction
    fn obfuscate(&self, signed_transaction: SignedTransaction) -> Result<TxAux>;

    /// Get a decrypted transaction by a given tx_id
    fn decrypt_tx(&self, txid: TxId, private_key: &PrivateKey) -> Result<Transaction>;
}
