mod measurement;
mod quote_body;
mod report_body;

pub use self::{measurement::Measurement, quote_body::QuoteBody, report_body::ReportBody};

/// Length of quote (without signature). For more details, refer to "QUOTE Structure" section in
/// https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
const QUOTE_LEN: usize = 432;

/// Quote returned by QE (without signature)
#[derive(Debug)]
pub struct Quote {
    /// Body of the quote
    pub body: QuoteBody,
    /// Report body of the quote
    pub report_body: ReportBody,
}

impl Quote {
    pub fn try_copy_from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != QUOTE_LEN {
            return None;
        }

        let body = QuoteBody::try_copy_from(&bytes[0..48])?;
        let report_body = ReportBody::try_copy_from(&bytes[48..432])?;

        Some(Self { body, report_body })
    }
}
