//! Transaction building
mod default_transaction_builder;
mod unauthorized_transaction_builder;

pub use default_transaction_builder::DefaultTransactionBuilder;
pub use unauthorized_transaction_builder::UnauthorizedTransactionBuilder;

use secstr::SecUtf8;

use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::Result;

use crate::UnspentTransactions;

/// Interface for transaction building from output addresses and amount. This trait is also responsible for UTXO
/// selection.
pub trait TransactionBuilder: Send + Sync {
    /// Builds a transaction
    ///
    /// # Attributes
    ///
    /// - `name`: Name of wallet
    /// - `passphrase`: Passphrase of wallet
    /// - `outputs`: Transaction outputs
    /// - `attributes`: Transaction attributes,
    /// - `unspent_transactions`: Unspent transactions
    /// - `return_address`: Address to which change amount will get returned
    fn build(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        unspent_transactions: UnspentTransactions,
        return_address: ExtendedAddr,
    ) -> Result<TxAux>;
}
