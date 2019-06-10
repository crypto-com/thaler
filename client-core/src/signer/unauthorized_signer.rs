use secstr::SecUtf8;

use chain_core::tx::witness::TxWitness;
use client_common::{ErrorKind, Result};

use crate::{SelectedUnspentTransactions, Signer};

/// `TransactionBuilder` which returns `PermissionDenied` error for each function call.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnauthorizedSigner;

impl Signer for UnauthorizedSigner {
    fn sign<T: AsRef<[u8]>>(
        &self,
        _: &str,
        _: &SecUtf8,
        _: T,
        _: SelectedUnspentTransactions,
    ) -> Result<TxWitness> {
        Err(ErrorKind::PermissionDenied.into())
    }
}
