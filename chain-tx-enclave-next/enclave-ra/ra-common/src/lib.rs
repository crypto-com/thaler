mod quote;
mod report;

pub mod sp;

pub use self::{
    quote::{Measurement, Quote, QuoteBody, ReportBody},
    report::{
        AttestationReport, AttestationReportBody, EnclaveQuoteStatus,
        EnclaveQuoteStatusParsingError, QuoteParsingError, OID_EXTENSION_ATTESTATION_REPORT,
    },
};

/// 90 days
pub const DEFAULT_EXPIRATION_SECS: i64 = 7776000;
