use crate::program::Options;

use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use std::net::SocketAddr;

use chain_core::init::network::{get_network, get_network_id, init_chain_id};
use client_common::Result;
use client_common::{Error, ErrorKind};
use client_core::wallet::syncer::SyncerOptions;
use client_rpc_core::RpcHandler;
pub(crate) struct Server {
    host: String,
    port: u16,
    network_id: u8,
    storage_dir: String,
    websocket_url: String,

    sync_options: SyncerOptions,
}

impl Server {
    pub(crate) fn new(options: Options) -> Result<Server> {
        init_chain_id(&options.chain_id);
        let network_id = get_network_id();

        println!("Network type {:?} id {:02X}", get_network(), network_id);
        let mut light_client_peers: String = "".to_string();

        if !options.disable_light_client {
            if let Some(value) = options.light_client_peers {
                light_client_peers = value;
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid light-client-peers",
                ));
            }
        }

        Ok(Server {
            host: options.host,
            port: options.port,
            network_id,
            storage_dir: options.storage_dir,
            websocket_url: options.websocket_url,
            sync_options: SyncerOptions {
                enable_fast_forward: options.enable_fast_forward,
                disable_light_client: options.disable_light_client,
                enable_address_recovery: !options.disable_address_recovery,
                batch_size: options.batch_size,
                block_height_ensure: options.block_height_ensure,
                light_client_peers,
                light_client_trusting_period_seconds: options.light_client_trusting_period_seconds,
                light_client_trusting_height: options.light_client_trusting_height,
                light_client_trusting_blockhash: options.light_client_trusting_blockhash,
            },
        })
    }

    fn create_rpc_handler(&self) -> Result<RpcHandler> {
        if cfg!(feature = "mock-enclave") {
            log::warn!("{}", "WARNING: Using mock (non-enclave) infrastructure");
        }
        RpcHandler::new(
            &self.storage_dir,
            &self.websocket_url,
            self.network_id,
            self.sync_options.clone(),
            None,
        )
    }

    pub(crate) fn start(&mut self) -> Result<()> {
        let handler = self.create_rpc_handler()?;
        let server = ServerBuilder::new(handler.io)
            // TODO: Either make CORS configurable or make it more strict
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Any,
            ]))
            .start_http(&SocketAddr::new(self.host.parse().unwrap(), self.port))
            .expect("Unable to start JSON-RPC server");

        log::info!("server wait");
        server.wait();

        Ok(())
    }
}
