use std::net::SocketAddr;
use std::sync::Arc;

use failure::{Error, ResultExt};
use jsonrpc_http_server::jsonrpc_core;
use jsonrpc_http_server::jsonrpc_core::IoHandler;
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use structopt::StructOpt;

use signer_core::SecretsService;

use crate::address_rpc::{AddressRpc, AddressRpcImpl};
use crate::transaction_rpc::{TransactionRpc, TransactionRpcImpl};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "signer-rpc",
    about = "Basic JsonRPC server for secret management (using enclaves in the future), possibly TX generation and signing"
)]
pub enum Command {
    #[structopt(name = "run", about = "Starts JsonRPC server")]
    Run {
        #[structopt(name = "port", short, long, help = "Port of JsonRPC server")]
        port: u16,
    },
}

impl Command {
    pub fn execute(&self) -> Result<(), Error> {
        use Command::*;

        match self {
            Run { port } => self.run(*port),
        }
    }

    fn run(&self, port: u16) -> Result<(), Error> {
        let service = Arc::new(SecretsService::new()?);

        let mut io = IoHandler::new();
        let address_rpc = AddressRpcImpl::new(service.clone());
        let transaction_rpc = TransactionRpcImpl::new(service.clone());

        io.extend_with(address_rpc.to_delegate());
        io.extend_with(transaction_rpc.to_delegate());

        let server = ServerBuilder::new(io)
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Null,
            ]))
            .start_http(&SocketAddr::new("127.0.0.1".parse().unwrap(), port))
            .context("Unable to start RPC server")?;

        server.wait();

        Ok(())
    }
}

pub(crate) fn to_rpc_error(error: Error) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: error.to_string(),
        data: None,
    }
}
