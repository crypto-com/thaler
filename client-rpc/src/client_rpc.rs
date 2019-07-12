use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use client_common::balance::TransactionChange;
use client_core::wallet::WalletClient;
use client_network::network_ops::{DefaultNetworkOpsClient, NetworkOpsClient};

use crate::server::{rpc_error_from_string, to_rpc_error};

#[rpc]
pub trait ClientRpc {
    #[rpc(name = "query_client")]
    fn query_client(&self, request: ClientRequest) -> Result<String>;

    #[rpc(name = "create_deposit_bonded_stake_transaction")]
    fn create_deposit_bonded_stake_transaction(&self, request: ClientRequest) -> Result<String> {
        Ok("create_deposit_bonded_stake_transaction OK".to_string())
    }

    #[rpc(name = "create_withdraw_unbonded_stake_transaction")]
    fn create_withdraw_unbonded_stake_transaction(&self, request: ClientRequest) -> Result<String> {
        Ok("create_withdraw_unbonded_stake_transaction OK".to_string())
    }

    #[rpc(name = "create_withdraw_all_unbonded_stake_transaction")]
    fn create_withdraw_all_unbonded_stake_transaction(
        &self,
        request: ClientRequest,
    ) -> Result<String> {
        Ok("create_withdraw_all_unbonded_stake_transaction OK".to_string())
    }
}

pub struct ClientRpcImpl<T: NetworkOpsClient + Send + Sync> {
    client: T,
    chain_id: u8,
}

impl<T> ClientRpcImpl<T>
where
    T: NetworkOpsClient + Send + Sync,
{
    pub fn new(client: T, chain_id: u8) -> Self {
        ClientRpcImpl { client, chain_id }
    }
}

impl<T> ClientRpc for ClientRpcImpl<T>
where
    T: NetworkOpsClient + Send + Sync + 'static,
{
    fn query_client(&self, request: ClientRequest) -> Result<String> {
        Ok("apple".to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRequest {
    name: String,
    passphrase: SecUtf8,
}
