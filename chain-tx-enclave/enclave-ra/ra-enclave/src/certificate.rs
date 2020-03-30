use std::convert::TryFrom;

use chrono::{DateTime, Duration, Utc};
use rustls::{Certificate as RustlsCertificate, NoClientAuth, PrivateKey, ServerConfig, TLSError};

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
}

impl TryFrom<Certificate> for ServerConfig {
    type Error = TLSError;

    fn try_from(certificate: Certificate) -> Result<Self, Self::Error> {
        let mut config = ServerConfig::new(NoClientAuth::new());
        config.set_single_cert(vec![certificate.certificate], certificate.private_key)?;
        Ok(config)
    }
}
