use std::{fs::read, path::Path};

use thiserror::Error;
use webpki::{
    trust_anchor_util::cert_der_as_trust_anchor, EndEntityCert, TLSServerTrustAnchors, Time,
};
use x509_parser::x509::X509Certificate;

use crate::crypto::{pem_parser::pem_to_der, signature::VerificationKey};

static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[&webpki::RSA_PKCS1_2048_8192_SHA256];

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Signature error: {0}")]
    SignatureError(#[from] crate::crypto::signature::SignatureError),
    #[error("X.509 parsing error")]
    X509Error,
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("UTF-8 parsing error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("WebPKI error: {0}")]
    WebPKIError(#[from] webpki::Error),
    #[error("Bad certificate")]
    BadCertificate,
    #[error("Unauthorized certificate")]
    UnauthorizedCertificate,
}

#[derive(PartialEq, Debug)]
pub struct X509Cert {
    cert: Vec<u8>,
}

impl X509Cert {
    pub fn new_from_der(x509_der: &[u8]) -> Result<Self, CertificateError> {
        let cert = Self::parse(x509_der)?;
        VerificationKey::new_from_der(
            cert.tbs_certificate.subject_pki.subject_public_key.as_ref(),
        )?;
        Ok(Self {
            cert: x509_der.to_owned(),
        })
    }

    pub fn new_from_pem(x509_pem: &str) -> Result<Self, CertificateError> {
        let der = pem_to_der(x509_pem)?;
        Self::new_from_der(&der[..])
    }

    pub fn new_from_pem_file(x509_pem: impl AsRef<Path>) -> Result<Self, CertificateError> {
        let pem = String::from_utf8(read(x509_pem)?)?;
        Self::new_from_pem(&pem)
    }

    pub fn get_verification_key(&self) -> VerificationKey {
        let cert = Self::parse(&self.cert[..]).unwrap();
        VerificationKey::new_from_der(cert.tbs_certificate.subject_pki.subject_public_key.as_ref())
            .unwrap()
    }

    pub fn verify_cert(&self, immediate_cert: &Self) -> Result<(), CertificateError> {
        let anchors = vec![cert_der_as_trust_anchor(immediate_cert.as_ref()).unwrap()];
        let anchors = TLSServerTrustAnchors(&anchors);
        let time = Time::from_seconds_since_unix_epoch(1492441716);
        let cert = EndEntityCert::from(self.as_ref()).unwrap();
        cert.verify_is_valid_tls_server_cert(ALL_SIGALGS, &anchors, &[], time)?;
        Ok(())
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.cert
    }

    fn parse<'a>(x509_der: &'a [u8]) -> Result<X509Certificate<'a>, CertificateError> {
        x509_parser::parse_x509_der(x509_der)
            .map(|(_, cert)| cert)
            .map_err(|_| CertificateError::X509Error)
    }
}
