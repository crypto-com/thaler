//! Network operations on Crypto.com Chain
mod default_network_ops_client;

pub use self::default_network_ops_client::DefaultNetworkOpsClient;

use chain_core::init::coin::Coin;
use chain_core::state::account::Nonce;
use chain_core::state::account::StakedState;
use chain_core::state::account::{StakedStateAddress, StakedStateOpAttributes};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::Result;
use secstr::SecUtf8;

/// Interface for performing network operations on Crypto.com Chain
pub trait NetworkOpsClient {
    /// fetch current StakedState
    fn get_staked_state_account(
        &self,
        to_staked_account: StakedStateAddress,
    ) -> Result<StakedState>;

    /// fetch current StakedState nonce
    fn get_staked_state_nonce(&self, to_staked_account: StakedStateAddress) -> Result<Nonce>;

    /// creates a new transaction for bonding stake transaction with utxos
    fn create_deposit_bonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        inputs: Vec<TxoPointer>,
        to_staked_account: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux>;
    /// creates a new transaction for unbonding stake transaction
    fn create_unbond_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &ExtendedAddr,
        value: Coin,
        attributes: StakedStateOpAttributes,
        nonce: Nonce,
    ) -> Result<TxAux>;
    /// Creates a new transaction for withdrawing unbonded stake from an account
    fn create_withdraw_unbonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &ExtendedAddr,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        nonce: Nonce,
    ) -> Result<TxAux>;

    // TODO: Add `get_account_details()` functions
}
