use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use client_common::{ErrorKind, Result, Transaction};

use crate::{AddressDetails, Index};

/// `Index` which returns `PermissionDenied` error for each function call.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnauthorizedIndex;

impl Index for UnauthorizedIndex {
    fn address_details(&self, _address: &ExtendedAddr) -> Result<AddressDetails> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn transaction(&self, _id: &TxId) -> Result<Option<Transaction>> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn output(&self, _input: &TxoPointer) -> Result<TxOut> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<()> {
        Err(ErrorKind::PermissionDenied.into())
    }
}
