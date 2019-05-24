//! Transaction building
mod default_transaction_builder;
mod unauthorized_transaction_builder;

pub use default_transaction_builder::DefaultTransactionBuilder;
pub use unauthorized_transaction_builder::UnauthorizedTransactionBuilder;

use secstr::SecUtf8;

use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::Result;

use crate::WalletClient;

/// Interface for transaction building from output addresses and amount. This trait is also responsible for UTXO
/// selection.
pub trait TransactionBuilder: Send + Sync {
    /// Builds a transaction by returning extra coins to `return_address`.
    fn build<W: WalletClient>(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        wallet_client: &W,
    ) -> Result<TxAux>;
}
