use std::{collections::HashSet, sync::Arc, time::SystemTime};

use chrono::{DateTime, Duration, Utc};
use der_parser::oid::Oid;
use ra_common::{
    AttestationReport, AttestationReportBody, EnclaveQuoteStatus, OID_EXTENSION_ATTESTATION_REPORT,
};
use rustls::{
    internal::pemfile::certs, Certificate, ClientCertVerified, ClientCertVerifier, ClientConfig,
    DistinguishedNames, RootCertStore, ServerCertVerified, ServerCertVerifier, ServerConfig,
    TLSError,
};
use thiserror::Error;
use webpki::{
    DNSName, DNSNameRef, EndEntityCert, SignatureAlgorithm, TLSServerTrustAnchors, Time,
    TrustAnchor, ECDSA_P256_SHA256, RSA_PKCS1_2048_8192_SHA256,
};
use x509_parser::{parse_x509_der, x509};

use crate::{EnclaveCertVerifierConfig, EnclaveInfo};

static SUPPORTED_SIG_ALGS: &[&SignatureAlgorithm] = &[&ECDSA_P256_SHA256];

pub struct EnclaveCertVerifier {
    root_cert_store: RootCertStore,
    valid_enclave_quote_statuses: HashSet<EnclaveQuoteStatus>,
    report_validity_duration: Duration,
    enclave_info: Option<EnclaveInfo>,
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
            enclave_info: config.enclave_info,
        })
    }

    /// Verifies certificate and return the public key
    /// the returned public key is in uncompressed raw format (65 bytes)
    pub fn verify_cert(
        &self,
        certificate: &[u8],
        now: DateTime<Utc>,
    ) -> Result<Vec<u8>, EnclaveCertVerifierError> {
        let (_, certificate) = parse_x509_der(certificate)
            .map_err(|_| EnclaveCertVerifierError::CertificateParsingError)?;

        let x509::Validity {
            not_before,
            not_after,
        } = certificate.tbs_certificate.validity;
        let now_sec = now.timestamp();
        if now_sec < not_before.to_timespec().sec {
            return Err(EnclaveCertVerifierError::CertificateExpired);
        }
        if now_sec >= not_after.to_timespec().sec {
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
                self.verify_attestation_report(extension.value, public_key, now)?;
            }
        }

        if attestation_report_received {
            Ok(public_key.to_vec())
        } else {
            Err(EnclaveCertVerifierError::MissingAttestationReport)
        }
    }

    /// Verifies attestation report
    fn verify_attestation_report(
        &self,
        attestation_report: &[u8],
        public_key: &[u8],
        now: DateTime<Utc>,
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

        self.verify_attestation_report_body(&attestation_report.body, public_key, now)?;

        log::info!("Attestation report is valid!");
        Ok(())
    }

    fn verify_attestation_report_body(
        &self,
        attestation_report_body: &[u8],
        public_key: &[u8],
        now: DateTime<Utc>,
    ) -> Result<(), EnclaveCertVerifierError> {
        let attestation_report_body: AttestationReportBody =
            serde_json::from_slice(attestation_report_body)?;

        let mut attestation_report_timestamp = attestation_report_body.timestamp.clone();
        attestation_report_timestamp.push_str("+00:00");

        let attestation_report_time: DateTime<Utc> = attestation_report_timestamp.parse()?;

        if attestation_report_time + self.report_validity_duration < now {
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

        if let Some(ref enclave_info) = self.enclave_info {
            if enclave_info.mr_signer != quote.report_body.measurement.mr_signer {
                return Err(EnclaveCertVerifierError::MeasurementMismatch);
            }

            if let Some(ref mr_enclave) = enclave_info.mr_enclave {
                if mr_enclave != &quote.report_body.measurement.mr_enclave {
                    return Err(EnclaveCertVerifierError::MeasurementMismatch);
                }
            }

            if enclave_info.cpu_svn > quote.report_body.cpu_svn {
                return Err(EnclaveCertVerifierError::MeasurementMismatch);
            }

            if enclave_info.isv_svn > quote.report_body.isv_svn {
                return Err(EnclaveCertVerifierError::MeasurementMismatch);
            }
        }

        Ok(())
    }

    /// Converts enclave certificate verifier into client config expected by `rustls`
    pub fn into_client_config(self) -> ClientConfig {
        let mut config = ClientConfig::new();
        config.dangerous().set_certificate_verifier(Arc::new(self));
        config
    }

    /// Converts enclave certificate verifier into server config expected by `rustls`
    pub fn into_server_config(self) -> ServerConfig {
        ServerConfig::new(Arc::new(self))
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
            self.verify_cert(&cert.0, Utc::now())?;
        }

        Ok(ServerCertVerified::assertion())
    }
}

impl ClientCertVerifier for EnclaveCertVerifier {
    fn client_auth_root_subjects(&self, _sni: Option<&DNSName>) -> Option<DistinguishedNames> {
        None
    }

    fn verify_client_cert(
        &self,
        presented_certs: &[Certificate],
        _sni: Option<&DNSName>,
    ) -> Result<ClientCertVerified, TLSError> {
        if presented_certs.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }

        for cert in presented_certs {
            self.verify_cert(&cert.0, Utc::now())?;
        }

        Ok(ClientCertVerified::assertion())
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
    #[error("Enclave details does not match with the ones provided in configuration")]
    MeasurementMismatch,
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
