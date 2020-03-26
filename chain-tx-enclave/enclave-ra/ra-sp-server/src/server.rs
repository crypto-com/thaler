use std::{
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::Arc,
    thread,
};

use ra_common::sp::protocol::{Request, Response};
use thiserror::Error;

use crate::{
    config::SpRaConfig,
    context::{SpRaContext, SpRaContextError},
};

/// SP TCP server for enclave remote attestation
pub struct SpRaServer {
    context: Arc<SpRaContext>,
}

impl SpRaServer {
    /// Creates a new instance of SP TCP server for remote attestation
    pub fn new(config: SpRaConfig) -> Result<Self, SpRaServerError> {
        let context = Arc::new(SpRaContext::new(config)?);

        Ok(Self { context })
    }

    pub fn run(&self, addrs: impl ToSocketAddrs) -> Result<(), SpRaServerError> {
        let listener = TcpListener::bind(addrs)?;

        for stream in listener.incoming() {
            let stream = stream?;
            let context = self.context.clone();

            thread::spawn(move || {
                if let Err(e) = handle_connection(&context, stream) {
                    log::error!("SP RA error: {}", e);
                }
            });
        }

        Ok(())
    }
}

fn handle_connection(context: &SpRaContext, stream: TcpStream) -> Result<(), SpRaServerError> {
    loop {
        let request: Request = bincode::deserialize_from(&stream)?;

        log::debug!("Received request: {:?}", request);

        let response = match request {
            Request::GetTargetInfo => {
                let target_info = context.get_target_info().to_vec();

                Response::GetTargetInfo { target_info }
            }
            Request::GetQuote { report } => {
                let sig_rl = context.get_sig_rl()?.unwrap_or_default();
                let quote_result = context.get_quote(report, sig_rl)?;

                Response::GetQuote { quote_result }
            }
            Request::GetAttestationReport { ref quote } => {
                let attestation_report = context.verify_quote(quote)?;

                Response::GetAttestationReport { attestation_report }
            }
        };

        log::debug!("Sending response: {:?}", response);

        bincode::serialize_into(&stream, &response)?;
    }
}

#[derive(Debug, Error)]
pub enum SpRaServerError {
    #[error("Bincode error: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("RA context error: {0}")]
    RaContextError(#[from] SpRaContextError),
}
