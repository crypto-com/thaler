use secstr::SecUtf8;

use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::{ErrorKind, Result, SignedTransaction};

use crate::{UnspentTransactions, WalletTransactionBuilder};

/// Implementation of `WalletTransactionBuilder` which always returns
/// permission denied
#[derive(Debug, Default, Clone, Copy)]
pub struct UnauthorizedWalletTransactionBuilder;

impl WalletTransactionBuilder for UnauthorizedWalletTransactionBuilder {
    fn build_transfer_tx(
        &self,
        _: &str,
        _: &SecUtf8,
        _: UnspentTransactions,
        _: Vec<TxOut>,
        _: ExtendedAddr,
        _: TxAttributes,
    ) -> Result<TxAux> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn obfuscate(&self, _: SignedTransaction) -> Result<TxAux> {
        Err(ErrorKind::PermissionDenied.into())
    }
}
