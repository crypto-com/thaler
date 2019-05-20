use secstr::SecStr;

use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::{ErrorKind, Result};

use crate::{TransactionBuilder, WalletClient};

/// `TransactionBuilder` which returns `PermissionDenied` error for each function call.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnauthorizedTransactionBuilder;

impl TransactionBuilder for UnauthorizedTransactionBuilder {
    fn build<W: WalletClient>(
        &self,
        _name: &str,
        _passphrase: &SecStr,
        _outputs: Vec<TxOut>,
        _attributes: TxAttributes,
        _wallet_client: &W,
    ) -> Result<TxAux> {
        Err(ErrorKind::PermissionDenied.into())
    }
}
