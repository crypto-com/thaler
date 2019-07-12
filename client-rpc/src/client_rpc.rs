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
use chain_core::state::account::{StakedStateAddress, StakedStateOpAttributes};
use chain_core::tx::data::input::TxoPointer;
use std::str::FromStr;
#[rpc]
pub trait ClientRpc {
    #[rpc(name = "query_client")]
    fn query_client(&self, request: ClientRequest) -> Result<String>;

    #[rpc(name = "create_deposit_bonded_stake_transaction")]
    fn create_deposit_bonded_stake_transaction(&self, request: ClientRequest) -> Result<String>;

    #[rpc(name = "create_unbond_stake_transaction")]
    fn create_unbond_stake_transaction(&self, request: CreateUnbondStakeTransactionRequest) -> Result<String>;

    #[rpc(name = "create_withdraw_all_unbonded_stake_transaction")]
    fn create_withdraw_all_unbonded_stake_transaction(
        &self,
        request: ClientRequest,
    ) -> Result<String>;
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
        let m = serde_json::to_string(&request).unwrap();
        Ok(m.to_string())
    }

    fn create_deposit_bonded_stake_transaction(&self, request: ClientRequest) -> Result<String> {
        let utxo: Vec<TxoPointer> = vec![];
        let addr: StakedStateAddress =
            StakedStateAddress::from_str(request.address.as_str()).unwrap();

        let attr: StakedStateOpAttributes = StakedStateOpAttributes::new(self.chain_id);
        let result = self.client.create_deposit_bonded_stake_transaction(
            request.name.as_str(),
            &SecUtf8::from(request.passphrase),
            utxo,
            addr,
            attr,
        );
        Ok("Success create_deposit_bonded_stake_transaction".to_string())
    }

    fn create_unbond_stake_transaction(&self, request: CreateUnbondStakeTransactionRequest) -> Result<String> {
        let value = Coin::from_str(request.amount.as_str()).unwrap();
        let attr: StakedStateOpAttributes = StakedStateOpAttributes::new(self.chain_id);
        let addr: StakedStateAddress =
            StakedStateAddress::from_str(request.address.as_str()).unwrap();

        let result = self.client.create_unbond_stake_transaction(
            request.name.as_str(),
            &SecUtf8::from(request.passphrase),
            &addr,
            value,
            attr,
        );

        Ok("Success create_unbond_stake_transaction".to_string())
    }

    fn create_withdraw_all_unbonded_stake_transaction(
        &self,
        request: ClientRequest,
    ) -> Result<String> {
        let addr: StakedStateAddress =
            StakedStateAddress::from_str(request.address.as_str()).unwrap();
        let utxo: Vec<TxOut> = vec![];
        let attr = TxAttributes::new(self.chain_id);

        let result = self.client.create_withdraw_unbonded_stake_transaction(
            request.name.as_str(),
            &SecUtf8::from(request.passphrase),
            &addr,
            utxo,
            attr,
        );
        Ok("Success create_withdraw_unbonded_stake_transaction".to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRequest {
    name: String,
    passphrase: SecUtf8,
    address: String,
}



#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUnbondStakeTransactionRequest {
    name: String,
    passphrase: SecUtf8,
    address: String,
    amount: String, // u64 as String
}