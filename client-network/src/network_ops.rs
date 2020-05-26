//! Network operations on Crypto.com Chain
mod default_network_ops_client;

pub use self::default_network_ops_client::DefaultNetworkOpsClient;
use chain_core::init::coin::Coin;
use chain_core::state::account::{
    CouncilNode, StakedState, StakedStateAddress, StakedStateOpAttributes,
};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::tendermint::types::{Genesis, StatusResponse};
use client_common::{ErrorKind, Result, ResultExt, SecKey};
use client_core::types::TransactionPending;

/// Interface for performing network operations on Crypto.com Chain
pub trait NetworkOpsClient: Send + Sync {
    /// calculate the deposit fee
    fn calculate_deposit_fee(&self) -> Result<Coin>;

    /// creates a new transaction for bonding stake transaction with utxos
    fn create_deposit_bonded_stake_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        transaction: Vec<(TxoPointer, TxOut)>,
        to_address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
        verify_staking: bool,
    ) -> Result<(TxAux, TransactionPending)>;

    /// creates a new transaction for unbonding stake transaction
    fn create_unbond_stake_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        address: StakedStateAddress,
        value: Coin,
        attributes: StakedStateOpAttributes,
        verify_staking: bool,
    ) -> Result<TxAux>;

    /// Creates a new transaction for withdrawing unbonded stake from an account
    fn create_withdraw_unbonded_stake_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        from_address: &StakedStateAddress,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        verify_staking: bool,
    ) -> Result<(TxAux, TransactionPending)>;

    /// Creates a new transaction for withdrawing all unbonded stake from an account
    fn create_withdraw_all_unbonded_stake_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        from_address: &StakedStateAddress,
        to_address: ExtendedAddr,
        attributes: TxAttributes,
        verify_staking: bool,
    ) -> Result<(TxAux, TransactionPending)>;

    /// Creates a new transaction for un-jailing a previously jailed account
    fn create_unjail_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
        verify_staking: bool,
    ) -> Result<TxAux>;

    /// Creates a new transaction for a node joining validator set
    fn create_node_join_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        staking_account_address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
        node_metadata: CouncilNode,
        verify_staking: bool,
    ) -> Result<TxAux>;

    /// Returns staked stake corresponding to given address
    fn get_staked_state(
        &self,
        name: &str,
        address: &StakedStateAddress,
        verify: bool,
    ) -> Result<StakedState> {
        self.get_staking(name, address, verify)?
            .err_kind(ErrorKind::InvalidInput, || "staking not found")
    }

    /// Returns staked stake corresponding to given address
    fn get_staking(
        &self,
        name: &str,
        address: &StakedStateAddress,
        verify: bool,
    ) -> Result<Option<StakedState>>;

    /// Return genesis of tendermint
    fn get_genesis(&self) -> Result<Genesis>;

    /// Return status response
    fn get_status(&self) -> Result<StatusResponse>;
}
