//! This crate provides types for connecting to remote attestation SP server
//!
//! ## Usage
//!
//! ```rust,no_run
//! use ra_sp_client::SpRaClient;
//!
//! let address = "0.0.0.0:8989";
//! let client = SpRaClient::connect(address).unwrap();
//!
//! let target_info = client.get_target_info().unwrap();
//!
//! // Generate a enclave report using received target info
//! let report = vec![];
//!
//! let quote_result = client.get_quote(report).unwrap();
//!
//! // Verify the QE report in `quote_result`
//! let attestation_report = client.get_attestation_report(quote_result.quote).unwrap();
//! ```
mod client;

pub use self::client::{SpRaClient, SpRaClientError};
