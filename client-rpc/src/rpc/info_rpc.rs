use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

use crate::to_rpc_error;
use client_common::tendermint::types::{Genesis, StatusResponse};
use client_network::NetworkOpsClient;

#[rpc(server)]
pub trait InfoRpc: Send + Sync {
    #[rpc(name = "genesis")]
    fn genesis(&self) -> Result<Genesis>;
    #[rpc(name = "status")]
    fn status(&self) -> Result<StatusResponse>;
}

pub struct InfoRpcImpl<N>
where
    N: NetworkOpsClient,
{
    ops_client: N,
}

impl<N> InfoRpcImpl<N>
where
    N: NetworkOpsClient,
{
    pub fn new(ops_client: N) -> Self {
        InfoRpcImpl { ops_client }
    }
}

impl<N> InfoRpc for InfoRpcImpl<N>
where
    N: NetworkOpsClient + 'static,
{
    fn genesis(&self) -> Result<Genesis> {
        self.ops_client.get_genesis().map_err(to_rpc_error)
    }
    fn status(&self) -> Result<StatusResponse> {
        self.ops_client.get_status().map_err(to_rpc_error)
    }
}
