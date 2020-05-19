//! This crate provides types to create a TLS server in enclave with remote attestation.
//!
//! # Note
//!
//! Implementation follows techniques in https://arxiv.org/ftp/arxiv/papers/1801/1801.05863.pdf
//!
//! # Usage
//!
//! ```rust,no_run
//! use std::convert::TryInto;
//!
//! use ra_enclave::{EnclaveRaConfig, EnclaveRaContext};
//! use rustls::ServerConfig;
//!
//! let config = EnclaveRaConfig { sp_addr: "<TCP address of SP server>".to_string(), certificate_validity_secs: 86400 };
//! let context = EnclaveRaContext::new(&config).unwrap();
//! let certificate = context.get_certificate().unwrap();
//!
//! let mut server_config = ServerConfig::new(NoClientAuth::new());
//! certificate.configure_server_config(&mut server_config).unwrap();
//!
//! // This `server_config` can now be used to create a `rustls::Stream`.
//! ```
mod certificate;
mod cmac;
mod config;
mod context;

pub use self::{
    certificate::Certificate,
    config::EnclaveRaConfig,
    context::{EnclaveRaContext, EnclaveRaContextError},
};
