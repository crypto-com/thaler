use std::convert::TryInto;

use aesm_client::{AesmClient, QuoteInfo, QuoteType};
use hex::FromHex;
use ra_common::{sp::QuoteResult, AttestationReport};
use thiserror::Error;

use crate::{
    config::SpRaConfig,
    ias_client::{IasClient, IasClientError},
};

/// Wraps all the SP operations required for remote attestation
pub struct SpRaContext {
    aesm_client: AesmClient,
    ias_client: IasClient,
    spid: [u8; 16],
    quote_info: QuoteInfo,
    quote_type: String,
}

impl SpRaContext {
    /// Creates a new SP remote attestation context
    pub fn new(config: SpRaConfig) -> Result<Self, SpRaContextError> {
        let aesm_client = AesmClient::new();
        let quote_info = aesm_client
            .init_quote()
            .map_err(SpRaContextError::AesmError)?;
        let quote_type = config.quote_type;

        let ias_client = IasClient::new(config.ias_key);

        let spid = <[u8; 16]>::from_hex(config.spid).map_err(SpRaContextError::InvalidSpid)?;

        Ok(Self {
            aesm_client,
            ias_client,
            spid,
            quote_info,
            quote_type,
        })
    }

    /// Returns target info obtained from AESM
    pub fn get_target_info(&self) -> &[u8] {
        self.quote_info.target_info()
    }

    /// Gets SigRL (Signature revocation list) from IAS
    pub fn get_sig_rl(&self) -> Result<Option<Vec<u8>>, SpRaContextError> {
        let gid = self
            .quote_info
            .gid()
            .try_into()
            .map_err(SpRaContextError::InvalidGid)?;

        self.ias_client.get_sig_rl(gid).map_err(Into::into)
    }

    /// Generates a new quote from QE using AESM
    pub fn get_quote(
        &self,
        report: Vec<u8>,
        sig_rl: Vec<u8>,
    ) -> Result<QuoteResult, SpRaContextError> {
        let quote_result = self
            .aesm_client
            .get_quote(
                &self.quote_info,
                report,
                self.spid.to_vec(),
                sig_rl,
                parse_quote_type(&self.quote_type)?,
                vec![0; 16],
            )
            .map_err(SpRaContextError::AesmError)?;

        let quote = quote_result.quote().to_vec();
        let qe_report = quote_result.qe_report().to_vec();

        Ok(QuoteResult { quote, qe_report })
    }

    /// Verifies quote using IAS
    pub fn verify_quote(&self, quote: &[u8]) -> Result<AttestationReport, SpRaContextError> {
        self.ias_client
            .verify_attestation_evidence(quote)
            .map_err(Into::into)
    }
}

fn parse_quote_type(quote_type: &str) -> Result<QuoteType, SpRaContextError> {
    match quote_type {
        "Linkable" => Ok(QuoteType::Linkable),
        "Unlinkable" => Ok(QuoteType::Unlinkable),
        _ => Err(SpRaContextError::InvalidQuoteType),
    }
}

#[derive(Debug, Error)]
pub enum SpRaContextError {
    #[error("AESM error: {0}")]
    AesmError(aesm_client::Error),
    #[error("IAS client error: {0}")]
    IasError(#[from] IasClientError),
    #[error("Invalid GID from AESM client: {0}")]
    InvalidGid(#[source] std::array::TryFromSliceError),
    #[error("Invalid quote type provided in configuration (possible values: `Linkable` or `Unlinkable`)")]
    InvalidQuoteType,
    #[error("Invalid SPID: {0}")]
    InvalidSpid(#[source] hex::FromHexError),
}
