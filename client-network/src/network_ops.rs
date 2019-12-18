//! Network operations on Crypto.com Chain
mod default_network_ops_client;

pub use self::default_network_ops_client::DefaultNetworkOpsClient;

use secstr::SecUtf8;

use chain_core::init::coin::Coin;
use chain_core::state::account::{
    CouncilNode, StakedState, StakedStateAddress, StakedStateOpAttributes,
};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::Result;
use client_core::types::TransactionPending;

/// Interface for performing network operations on Crypto.com Chain
pub trait NetworkOpsClient: Send + Sync {
    /// creates a new transaction for bonding stake transaction with utxos
    fn create_deposit_bonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        inputs: Vec<TxoPointer>,
        to_address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux>;

    /// creates a new transaction for unbonding stake transaction
    fn create_unbond_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: StakedStateAddress,
        value: Coin,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux>;

    /// Creates a new transaction for withdrawing unbonded stake from an account
    fn create_withdraw_unbonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &StakedStateAddress,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
    ) -> Result<(TxAux, TransactionPending)>;

    /// Creates a new transaction for withdrawing all unbonded stake from an account
    fn create_withdraw_all_unbonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &StakedStateAddress,
        to_address: ExtendedAddr,
        attributes: TxAttributes,
    ) -> Result<(TxAux, TransactionPending)>;

    /// Creates a new transaction for un-jailing a previously jailed account
    fn create_unjail_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux>;

    /// Creates a new transaction for a node joining validator set
    fn create_node_join_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        staking_account_address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
        node_metadata: CouncilNode,
    ) -> Result<TxAux>;

    /// Returns staked stake corresponding to given address
    fn get_staked_state(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: &StakedStateAddress,
    ) -> Result<StakedState>;
}
