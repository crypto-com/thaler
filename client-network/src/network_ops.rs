//! Network operations on Crypto.com Chain
mod default_network_ops_client;

pub use self::default_network_ops_client::DefaultNetworkOpsClient;

use secstr::SecUtf8;

use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::Result;

/// Interface for performing network operations on Crypto.com Chain
pub trait NetworkOpsClient {
    /// Creates a new transaction for withdrawing unbonded stake from an account
    fn create_withdraw_unbonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &ExtendedAddr,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
    ) -> Result<TxAux>;

    // TODO: Add `create_deposit_bonded_stake_transaction()`, `create_unbond_stake_transaction()` and `get_account_details()` functions
}
