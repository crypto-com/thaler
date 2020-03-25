use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use client_common::{ErrorKind, Result, Transaction};

use crate::unspent_transactions::SelectedUnspentTransactions;
use crate::{SignCondition, Signer};

/// `TransactionBuilder` which returns `PermissionDenied` error for each function call.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnauthorizedSigner;

impl Signer for UnauthorizedSigner {
    fn schnorr_sign_transaction(
        &self,
        _: &Transaction,
        _: &SelectedUnspentTransactions<'_>,
    ) -> Result<TxWitness> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn schnorr_sign_condition(&self, _: &ExtendedAddr) -> Result<SignCondition> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn schnorr_sign(&self, _: &Transaction, _: &ExtendedAddr) -> Result<TxInWitness> {
        Err(ErrorKind::PermissionDenied.into())
    }
}
