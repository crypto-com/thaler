use std::net::{TcpStream, ToSocketAddrs};

use bincode::{deserialize_from, serialize_into};
use thiserror::Error;

use ra_common::{
    sp::{
        protocol::{Request, Response},
        QuoteResult,
    },
    AttestationReport,
};

/// Client to connect and send requests to SP server for remote attestation
pub struct SpRaClient {
    stream: TcpStream,
}

impl SpRaClient {
    /// Connects to SP server running at `addr` for remote attestation
    pub fn connect(addr: impl ToSocketAddrs) -> Result<Self, SpRaClientError> {
        let stream = TcpStream::connect(addr)?;

        Ok(Self { stream })
    }

    /// Get target info obtained from AESM
    pub fn get_target_info(&self) -> Result<Vec<u8>, SpRaClientError> {
        let request = Request::GetTargetInfo;
        serialize_into(&self.stream, &request)?;

        let response: Response = deserialize_from(&self.stream)?;

        match response {
            Response::GetTargetInfo { target_info } => Ok(target_info),
            _ => Err(SpRaClientError::UnexpectedResponse(response)),
        }
    }

    /// Generates a new quote from QE using AESM
    pub fn get_quote(&self, report: Vec<u8>) -> Result<QuoteResult, SpRaClientError> {
        let request = Request::GetQuote { report };
        serialize_into(&self.stream, &request)?;

        let response: Response = deserialize_from(&self.stream)?;

        match response {
            Response::GetQuote { quote_result } => Ok(quote_result),
            _ => Err(SpRaClientError::UnexpectedResponse(response)),
        }
    }

    /// Generate attestation report using IAS
    pub fn get_attestation_report(
        &self,
        quote: Vec<u8>,
    ) -> Result<AttestationReport, SpRaClientError> {
        let request = Request::GetAttestationReport { quote };
        serialize_into(&self.stream, &request)?;

        let response: Response = deserialize_from(&self.stream)?;

        match response {
            Response::GetAttestationReport { attestation_report } => Ok(attestation_report),
            _ => Err(SpRaClientError::UnexpectedResponse(response)),
        }
    }
}

#[derive(Debug, Error)]
pub enum SpRaClientError {
    #[error("Bincode error: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Unexpected response: {0:?}")]
    UnexpectedResponse(Response),
}
