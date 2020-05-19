use chrono::{DateTime, Duration, Utc};
use rustls::{Certificate as RustlsCertificate, ClientConfig, PrivateKey, ServerConfig, TLSError};

#[derive(Debug, Clone)]
/// Holds a X.509 certificate and its creation time
pub struct Certificate {
    /// X.509 certificate
    pub certificate: RustlsCertificate,
    /// Certificate creation time
    pub created: DateTime<Utc>,
    /// Private key used for signing certificate
    pub private_key: PrivateKey,
}

impl Certificate {
    /// Checks if current certificate is valid or not
    pub fn is_valid(&self, validity_duration: Duration) -> bool {
        let current_time = Utc::now();
        self.created + validity_duration >= current_time
    }

    /// Sets current certificate in given `rustls` server config
    pub fn configure_server_config(self, server_config: &mut ServerConfig) -> Result<(), TLSError> {
        server_config.set_single_cert(vec![self.certificate], self.private_key)
    }

    /// Sets current certificate in given `rustls` client config
    pub fn configure_client_config(self, client_config: &mut ClientConfig) -> Result<(), TLSError> {
        client_config.set_single_client_cert(vec![self.certificate], self.private_key)
    }
}
