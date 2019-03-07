use std::sync::Arc;

use jsonrpc_derive::rpc;
use jsonrpc_http_server::jsonrpc_core;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use signer_core::{AddressType, SecretsService};

use crate::command::to_rpc_error;

#[rpc]
pub trait AddressRpc {
    #[rpc(name = "generateAddress")]
    fn generate_address(&self, request: AddressRequest) -> jsonrpc_core::Result<String>;

    #[rpc(name = "getAddress")]
    fn get_address(&self, request: AddressRequest) -> jsonrpc_core::Result<AddressResponse>;
}

pub struct AddressRpcImpl {
    service: Arc<SecretsService>,
}

impl AddressRpcImpl {
    pub fn new(service: Arc<SecretsService>) -> Self {
        AddressRpcImpl { service }
    }
}

impl AddressRpc for AddressRpcImpl {
    fn generate_address(&self, request: AddressRequest) -> jsonrpc_core::Result<String> {
        if let Err(e) = self.service.generate(&request.name, &request.passphrase) {
            Err(to_rpc_error(e))
        } else {
            Ok("created".to_owned())
        }
    }

    fn get_address(&self, mut request: AddressRequest) -> jsonrpc_core::Result<AddressResponse> {
        let secrets = self
            .service
            .get(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;

        request.passphrase.zeroize();

        let response = AddressResponse {
            spend: secrets
                .get_address(AddressType::Spend)
                .map_err(to_rpc_error)?,
            view: secrets
                .get_address(AddressType::View)
                .map_err(to_rpc_error)?,
        };

        Ok(response)
    }
}

#[derive(Debug, Deserialize)]
pub struct AddressRequest {
    name: String,
    passphrase: String,
}

#[derive(Debug, Serialize)]
pub struct AddressResponse {
    spend: String,
    view: String,
}
