use std::net::{TcpStream, ToSocketAddrs};

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
        serde_json::to_writer(&self.stream, &request)?;

        let response: Response = serde_json::Deserializer::from_reader(&self.stream)
            .into_iter()
            .next()
            .transpose()?
            .ok_or_else(|| SpRaClientError::NoResponse)?;

        match response {
            Response::GetTargetInfo { target_info } => Ok(target_info),
            _ => Err(SpRaClientError::UnexpectedResponse(response)),
        }
    }

    /// Generates a new quote from QE using AESM
    pub fn get_quote(
        &self,
        report: Vec<u8>,
        nonce: [u8; 16],
    ) -> Result<QuoteResult, SpRaClientError> {
        let request = Request::GetQuote { report, nonce };
        serde_json::to_writer(&self.stream, &request)?;

        let response: Response = serde_json::Deserializer::from_reader(&self.stream)
            .into_iter()
            .next()
            .transpose()?
            .ok_or_else(|| SpRaClientError::NoResponse)?;

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
        serde_json::to_writer(&self.stream, &request)?;

        let response: Response = serde_json::Deserializer::from_reader(&self.stream)
            .into_iter()
            .next()
            .transpose()?
            .ok_or_else(|| SpRaClientError::NoResponse)?;

        match response {
            Response::GetAttestationReport { attestation_report } => Ok(attestation_report),
            _ => Err(SpRaClientError::UnexpectedResponse(response)),
        }
    }
}

#[derive(Debug, Error)]
pub enum SpRaClientError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("No response from SP server")]
    NoResponse,
    #[error("Unexpected response: {0:?}")]
    UnexpectedResponse(Response),
}
