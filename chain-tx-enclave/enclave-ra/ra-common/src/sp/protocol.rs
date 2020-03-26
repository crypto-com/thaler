use serde::{Deserialize, Serialize};

use crate::{sp::QuoteResult, AttestationReport};

/// Requests sent to SP by enclave
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Get target info obtained from AESM
    GetTargetInfo,
    /// Generates a new quote from QE using AESM
    GetQuote { report: Vec<u8> },
    /// Generate attestation report using IAS
    GetAttestationReport { quote: Vec<u8> },
}

/// Responses for request sent by enclave
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Response for target info request (includes target info obtained from AESM)
    GetTargetInfo { target_info: Vec<u8> },
    /// Response for quote request (includes quote and QE report)
    GetQuote { quote_result: QuoteResult },
    /// Response of attestation report request
    GetAttestationReport {
        attestation_report: AttestationReport,
    },
}
