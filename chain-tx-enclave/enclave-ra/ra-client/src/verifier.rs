use std::{collections::HashSet, sync::Arc, time::SystemTime};

use chrono::{DateTime, Duration, Utc};
use der_parser::oid::Oid;
use ra_common::{
    AttestationReport, AttestationReportBody, EnclaveQuoteStatus, OID_EXTENSION_ATTESTATION_REPORT,
};
use rustls::{
    internal::pemfile::certs, Certificate, ClientConfig, RootCertStore, ServerCertVerified,
    ServerCertVerifier, TLSError,
};
use thiserror::Error;
use webpki::{
    DNSNameRef, EndEntityCert, SignatureAlgorithm, TLSServerTrustAnchors, Time, TrustAnchor,
    ECDSA_P256_SHA256, RSA_PKCS1_2048_8192_SHA256,
};
use x509_parser::parse_x509_der;

use crate::EnclaveCertVerifierConfig;

static SUPPORTED_SIG_ALGS: &[&SignatureAlgorithm] = &[&ECDSA_P256_SHA256];

pub struct EnclaveCertVerifier {
    root_cert_store: RootCertStore,
    valid_enclave_quote_statuses: HashSet<EnclaveQuoteStatus>,
    report_validity_duration: Duration,
}

impl EnclaveCertVerifier {
    /// Creates a new instance of enclave certificate verifier
    pub fn new(config: EnclaveCertVerifierConfig) -> Result<Self, EnclaveCertVerifierError> {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store
            .add_pem_file(&mut config.signing_ca_cert_pem.as_ref())
            .map_err(|_| EnclaveCertVerifierError::CertificateParsingError)?;

        let mut valid_enclave_quote_statuses =
            HashSet::with_capacity(config.valid_enclave_quote_statuses.as_ref().len());

        for status in config.valid_enclave_quote_statuses.as_ref() {
            valid_enclave_quote_statuses.insert(status.parse()?);
        }

        let report_validity_duration = Duration::seconds(config.report_validity_secs.into());

        Ok(Self {
            root_cert_store,
            valid_enclave_quote_statuses,
            report_validity_duration,
        })
    }

    /// Verifies certificate
    fn verify_cert(&self, certificate: &[u8]) -> Result<(), EnclaveCertVerifierError> {
        let (_, certificate) = parse_x509_der(certificate)
            .map_err(|_| EnclaveCertVerifierError::CertificateParsingError)?;

        if certificate
            .tbs_certificate
            .validity
            .time_to_expiration()
            .is_none()
        {
            return Err(EnclaveCertVerifierError::CertificateExpired);
        }

        let attestation_report_oid = Oid::from(OID_EXTENSION_ATTESTATION_REPORT);
        let mut attestation_report_received = false;

        let public_key = certificate
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;

        for extension in certificate.tbs_certificate.extensions {
            if extension.oid == attestation_report_oid {
                attestation_report_received = true;
                self.verify_attestation_report(extension.value, public_key)?;
            }
        }

        if attestation_report_received {
            Ok(())
        } else {
            Err(EnclaveCertVerifierError::MissingAttestationReport)
        }
    }

    /// Verifies attestation report
    fn verify_attestation_report(
        &self,
        attestation_report: &[u8],
        public_key: &[u8],
    ) -> Result<(), EnclaveCertVerifierError> {
        log::info!("Verifying attestation report");

        let trust_anchors: Vec<TrustAnchor> = self
            .root_cert_store
            .roots
            .iter()
            .map(|cert| cert.to_trust_anchor())
            .collect();
        let time =
            Time::try_from(SystemTime::now()).map_err(|_| EnclaveCertVerifierError::TimeError)?;

        let attestation_report: AttestationReport = serde_json::from_slice(attestation_report)?;

        let signing_certs = certs(&mut attestation_report.signing_cert.as_ref())
            .map_err(|_| EnclaveCertVerifierError::CertificateParsingError)?;

        for signing_cert in signing_certs {
            let signing_cert = EndEntityCert::from(&signing_cert.0)?;

            signing_cert.verify_is_valid_tls_server_cert(
                SUPPORTED_SIG_ALGS,
                &TLSServerTrustAnchors(&trust_anchors),
                &[],
                time,
            )?;

            signing_cert.verify_signature(
                &RSA_PKCS1_2048_8192_SHA256,
                &attestation_report.body,
                &attestation_report.signature,
            )?;
        }

        self.verify_attestation_report_body(&attestation_report.body, public_key)?;

        log::info!("Attestation report is valid!");
        Ok(())
    }

    fn verify_attestation_report_body(
        &self,
        attestation_report_body: &[u8],
        public_key: &[u8],
    ) -> Result<(), EnclaveCertVerifierError> {
        let attestation_report_body: AttestationReportBody =
            serde_json::from_slice(attestation_report_body)?;

        let mut attestation_report_timestamp = attestation_report_body.timestamp.clone();
        attestation_report_timestamp.push_str("+00:00");

        let attestation_report_time: DateTime<Utc> = attestation_report_timestamp.parse()?;

        if attestation_report_time + self.report_validity_duration < Utc::now() {
            return Err(EnclaveCertVerifierError::OldAttestationReport);
        }

        if !self
            .valid_enclave_quote_statuses
            .contains(&attestation_report_body.isv_enclave_quote_status.parse()?)
        {
            return Err(EnclaveCertVerifierError::InvalidEnclaveQuoteStatus(
                attestation_report_body.isv_enclave_quote_status,
            ));
        }

        let quote = attestation_report_body.get_quote()?;

        if public_key.len() != 65
            && public_key[0] != 4
            && public_key[1..] != quote.report_body.report_data[..]
        {
            return Err(EnclaveCertVerifierError::PublicKeyMismatch);
        }

        Ok(())
    }
}

impl ServerCertVerifier for EnclaveCertVerifier {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        presented_certs: &[Certificate],
        _dns_name: DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        if presented_certs.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }

        for cert in presented_certs {
            self.verify_cert(&cert.0)?;
        }

        Ok(ServerCertVerified::assertion())
    }
}

impl From<EnclaveCertVerifier> for ClientConfig {
    fn from(verifier: EnclaveCertVerifier) -> Self {
        let mut config = Self::new();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(verifier));
        config
    }
}

#[derive(Debug, Error)]
pub enum EnclaveCertVerifierError {
    #[error("Enclave certificate expired")]
    CertificateExpired,
    #[error("Failed to parse server certificate")]
    CertificateParsingError,
    #[error("Unable to parse date time: {0}")]
    DateTimeParsingError(#[from] chrono::ParseError),
    #[error("Unable to parse enclave quote status: {0}")]
    EnclaveQuoteStatusParsingError(#[from] ra_common::EnclaveQuoteStatusParsingError),
    #[error("Invalid enclave quote status: {0}")]
    InvalidEnclaveQuoteStatus(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Attestation report not available in server certificate")]
    MissingAttestationReport,
    #[error("Attestation report is older than report validify duration")]
    OldAttestationReport,
    #[error("Public key in certificate does not match with the one in enclave quote")]
    PublicKeyMismatch,
    #[error("Unable to parse quote from attestation report body: {0}")]
    QuoteParsingError(#[from] ra_common::QuoteParsingError),
    #[error("Unable to get current time")]
    TimeError,
    #[error("Webpki error: {0}")]
    WebpkiError(#[from] webpki::Error),
}

impl From<EnclaveCertVerifierError> for TLSError {
    fn from(e: EnclaveCertVerifierError) -> Self {
        TLSError::General(e.to_string())
    }
}
