//! Types used in ra-sp-server and ra-sp-client
mod attestation_evidence;
mod quote_result;

pub mod protocol;

pub use self::{attestation_evidence::AttestationEvidence, quote_result::QuoteResult};
