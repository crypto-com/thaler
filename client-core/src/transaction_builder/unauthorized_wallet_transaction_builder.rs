use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::{ErrorKind, PrivateKey, Result, SecKey, SignedTransaction, Transaction};

use crate::{UnspentTransactions, WalletTransactionBuilder};
use chain_core::tx::data::TxId;

/// Implementation of `WalletTransactionBuilder` which always returns
/// permission denied
#[derive(Debug, Default, Clone, Copy)]
pub struct UnauthorizedWalletTransactionBuilder;

impl WalletTransactionBuilder for UnauthorizedWalletTransactionBuilder {
    fn build_transfer_tx(
        &self,
        _: &str,
        _: &SecKey,
        _: UnspentTransactions,
        _: Vec<TxOut>,
        _: ExtendedAddr,
        _: TxAttributes,
    ) -> Result<(TxAux, Vec<TxoPointer>, Coin)> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn obfuscate(&self, _: SignedTransaction) -> Result<TxAux> {
        Err(ErrorKind::PermissionDenied.into())
    }

    fn decrypt_tx(&self, _txid: TxId, _private_key: &PrivateKey) -> Result<Transaction> {
        Err(ErrorKind::PermissionDenied.into())
    }
}
