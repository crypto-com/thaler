use secstr::SecUtf8;

use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::{ErrorKind, Result};

use crate::{TransactionBuilder, UnspentTransactions};

/// Default implementation of `TransactionBuilder`
#[derive(Debug, Default, Clone, Copy)]
pub struct UnauthorizedTransactionBuilder;

impl TransactionBuilder for UnauthorizedTransactionBuilder {
    fn build(
        &self,
        _: &str,
        _: &SecUtf8,
        _: Vec<TxOut>,
        _: TxAttributes,
        _: UnspentTransactions,
        _: ExtendedAddr,
    ) -> Result<TxAux> {
        Err(ErrorKind::PermissionDenied.into())
    }
}
