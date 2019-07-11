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
use client_network::network_ops::DefaultNetworkOpsClient;
use client_network::network_ops::NetworkOpsClient;

use crate::server::{rpc_error_from_string, to_rpc_error};

#[rpc]
pub trait ClientRpc {
    #[rpc(name = "client_query")]
    fn client_query(&self, request: ClientRequest) -> Result<String>;
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
    fn client_query(&self, request: ClientRequest) -> Result<String> {
        Ok("apple".to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRequest {
    name: String,
    passphrase: SecUtf8,
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::DateTime;
    use std::time::SystemTime;

    use chain_core::init::coin::CoinError;
    use chain_core::tx::data::input::TxoPointer;
    use chain_core::tx::data::{Tx, TxId};
    use chain_core::tx::fee::{Fee, FeeAlgorithm};
    use chain_core::tx::TxAux;
    use client_common::balance::BalanceChange;
    use client_common::storage::MemoryStorage;
    use client_common::{Error, ErrorKind, Result as CommonResult, Transaction};
    use client_core::signer::DefaultSigner;
    use client_core::transaction_builder::DefaultTransactionBuilder;
    use client_core::wallet::DefaultWalletClient;
    use client_index::Index;

}
