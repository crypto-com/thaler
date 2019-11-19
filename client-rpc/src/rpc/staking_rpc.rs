use std::str::FromStr;

use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

use chain_core::init::coin::Coin;
use chain_core::state::account::{StakedState, StakedStateAddress, StakedStateOpAttributes};
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use client_common::{ErrorKind, PublicKey, Result as CommonResult, ResultExt};
use client_core::{MultiSigWalletClient, WalletClient};
use client_network::NetworkOpsClient;

use crate::server::{to_rpc_error, WalletRequest};

#[rpc]
pub trait StakingRpc: Send + Sync {
    #[rpc(name = "staking_depositStake")]
    fn deposit_stake(
        &self,
        request: WalletRequest,
        to_address: String,
        inputs: Vec<TxoPointer>,
    ) -> Result<String>;

    #[rpc(name = "staking_state")]
    fn state(&self, request: WalletRequest, address: StakedStateAddress) -> Result<StakedState>;

    #[rpc(name = "staking_unbondStake")]
    fn unbond_stake(
        &self,
        request: WalletRequest,
        staking_address: String,
        amount: Coin,
    ) -> Result<String>;

    #[rpc(name = "staking_withdrawAllUnbondedStake")]
    fn withdraw_all_unbonded_stake(
        &self,
        request: WalletRequest,
        from_address: String,
        to_address: String,
        view_keys: Vec<String>,
    ) -> Result<String>;

    #[rpc(name = "staking_unjail")]
    fn unjail(&self, request: WalletRequest, unjail_address: String) -> Result<String>;
}

pub struct StakingRpcImpl<T, N>
where
    T: WalletClient,
    N: NetworkOpsClient,
{
    client: T,
    ops_client: N,
    network_id: u8,
}

impl<T, N> StakingRpcImpl<T, N>
where
    T: WalletClient,
    N: NetworkOpsClient,
{
    pub fn new(client: T, ops_client: N, network_id: u8) -> Self {
        StakingRpcImpl {
            client,
            ops_client,
            network_id,
        }
    }
}

impl<T, N> StakingRpc for StakingRpcImpl<T, N>
where
    T: WalletClient + MultiSigWalletClient + 'static,
    N: NetworkOpsClient + 'static,
{
    fn deposit_stake(
        &self,
        request: WalletRequest,
        to_address: String,
        inputs: Vec<TxoPointer>,
    ) -> Result<String> {
        let addr = StakedStateAddress::from_str(&to_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!("Unable to deserialize to_address ({})", to_address),
                )
            })
            .map_err(to_rpc_error)?;
        let attr = StakedStateOpAttributes::new(self.network_id);
        let transaction = self
            .ops_client
            .create_deposit_bonded_stake_transaction(
                &request.name,
                &request.passphrase,
                inputs,
                addr,
                attr,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;

        Ok(hex::encode(transaction.tx_id()))
    }

    fn state(&self, request: WalletRequest, address: StakedStateAddress) -> Result<StakedState> {
        self.ops_client
            .get_staked_state(&request.name, &request.passphrase, &address)
            .map_err(to_rpc_error)
    }

    fn unbond_stake(
        &self,
        request: WalletRequest,
        staking_address: String,
        amount: Coin,
    ) -> Result<String> {
        let attr = StakedStateOpAttributes::new(self.network_id);
        let addr = StakedStateAddress::from_str(&staking_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!(
                        "Unable to deserialize staking address ({})",
                        staking_address
                    ),
                )
            })
            .map_err(to_rpc_error)?;

        let transaction = self
            .ops_client
            .create_unbond_stake_transaction(&request.name, &request.passphrase, addr, amount, attr)
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;

        Ok(hex::encode(transaction.tx_id()))
    }

    fn withdraw_all_unbonded_stake(
        &self,
        request: WalletRequest,
        from_address: String,
        to_address: String,
        view_keys: Vec<String>,
    ) -> Result<String> {
        let from_address = StakedStateAddress::from_str(&from_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!("Unable to deserialize from_address ({})", from_address),
                )
            })
            .map_err(to_rpc_error)?;
        let to_address = ExtendedAddr::from_str(&to_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!("Unable to deserialize to_address ({})", to_address),
                )
            })
            .map_err(to_rpc_error)?;
        let view_keys = view_keys
            .iter()
            .map(|key| PublicKey::from_str(key))
            .collect::<CommonResult<Vec<PublicKey>>>()
            .map_err(to_rpc_error)?;

        let view_key = self
            .client
            .view_key(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;

        let mut access_policies = vec![TxAccessPolicy {
            view_key: view_key.into(),
            access: TxAccess::AllData,
        }];

        for key in view_keys.iter() {
            access_policies.push(TxAccessPolicy {
                view_key: key.into(),
                access: TxAccess::AllData,
            });
        }

        let attributes = TxAttributes::new_with_access(self.network_id, access_policies);

        let transaction = self
            .ops_client
            .create_withdraw_all_unbonded_stake_transaction(
                &request.name,
                &request.passphrase,
                &from_address,
                to_address,
                attributes,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;

        Ok(hex::encode(transaction.tx_id()))
    }

    fn unjail(&self, request: WalletRequest, unjail_address: String) -> Result<String> {
        let unjail_address = StakedStateAddress::from_str(&unjail_address)
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    format!("Unable to deserialize unjail_address ({})", unjail_address),
                )
            })
            .map_err(to_rpc_error)?;

        let attributes = StakedStateOpAttributes::new(self.network_id);

        let transaction = self
            .ops_client
            .create_unjail_transaction(
                &request.name,
                &request.passphrase,
                unjail_address,
                attributes,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;

        Ok(hex::encode(transaction.tx_id()))
    }
}
