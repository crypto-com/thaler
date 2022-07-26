use std::{collections::HashSet, sync::Arc};

use chrono::{DateTime, Duration, Utc};
use der_parser::oid::Oid;
use lazy_static::lazy_static;
use ra_common::{
    AttestationReport, AttestationReportBody, EnclaveQuoteStatus, Quote,
    OID_EXTENSION_ATTESTATION_REPORT,
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

static SUPPORTED_SIG_ALGS: &[&SignatureAlgorithm] =
    &[&ECDSA_P256_SHA256, &RSA_PKCS1_2048_8192_SHA256];

lazy_static! {
    pub static ref ENCLAVE_CERT_VERIFIER: EnclaveCertVerifier = EnclaveCertVerifier::default();
}

pub trait AttestedCertVerifier: Clone {
    /// Verifies certificate and return the public key
    /// the returned public key is in uncompressed raw format (65 bytes)
    fn verify_attested_cert(
        &self,
        certificate: &[u8],
        now: DateTime<Utc>,
    ) -> Result<CertVerifyResult, EnclaveCertVerifierError>;
}

impl AttestedCertVerifier for EnclaveCertVerifier {
    fn verify_attested_cert(
        &self,
        certificate: &[u8],
        now: DateTime<Utc>,
    ) -> Result<CertVerifyResult, EnclaveCertVerifierError> {
        self.verify_cert(certificate, now)
    }
}

#[derive(Clone)]
pub struct EnclaveCertVerifier {
    root_cert_store: RootCertStore,
    valid_enclave_quote_statuses: HashSet<EnclaveQuoteStatus>,
    report_validity_duration: Duration,
    // TODO: make non-optional?
    enclave_info: Option<EnclaveInfo>,
}

impl Default for EnclaveCertVerifier {
    fn default() -> Self {
        EnclaveCertVerifier::new(Default::default()).expect("default verifier config is invalid")
    }
}

fn get_end_entity_certificate(
    certificate_chain: &[Certificate],
) -> Result<EndEntityCert, EnclaveCertVerifierError> {
    let signing_cert = certificate_chain
        .first()
        .ok_or(EnclaveCertVerifierError::MissingAttestationReportSigningCertificate)?;
    EndEntityCert::from(&signing_cert.0)
        .map_err(|_| EnclaveCertVerifierError::AttestationReportSigningCertificateParsingError)
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
    ) -> Result<CertVerifyResult, EnclaveCertVerifierError> {
        let (_, certificate) = parse_x509_der(certificate)
            .map_err(|_| EnclaveCertVerifierError::CertificateParsingError)?;

        let x509::Validity {
            not_before,
            not_after,
        } = certificate.tbs_certificate.validity;
        let now_sec = now.timestamp();

        if now_sec < not_before.timestamp() {
            return Err(EnclaveCertVerifierError::CertificateNotBegin);
        }
        if now_sec >= not_after.timestamp() {
            return Err(EnclaveCertVerifierError::CertificateExpired);
        }

        let attestation_report_oid = Oid::from(OID_EXTENSION_ATTESTATION_REPORT)
            .expect("Unable to parse attestation report OID");

        if certificate
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .len()
            != 65
        {
            return Err(EnclaveCertVerifierError::PublicKeyMismatch);
        }

        let mut public_key = [0; 65];
        public_key.copy_from_slice(
            certificate
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data,
        );

        let extension = certificate
            .tbs_certificate
            .extensions
            .iter()
            .find(|ext| ext.0 == &attestation_report_oid)
            .ok_or(EnclaveCertVerifierError::MissingAttestationReport)?;

        let quote = self.verify_attestation_report(extension.1.value, &public_key, now)?;

        Ok(CertVerifyResult { public_key, quote })
    }

    fn get_trust_anchor(&self) -> Vec<TrustAnchor> {
        self.root_cert_store
            .roots
            .iter()
            .map(|cert| cert.to_trust_anchor())
            .collect()
    }

    fn verify_end_entity_certificate(
        &self,
        end_entity_certificate: &EndEntityCert,
        intermediate_certs: &[Certificate],
        now: DateTime<Utc>,
    ) -> Result<(), webpki::Error> {
        let trust_anchors = self.get_trust_anchor();
        let time = Time::from_seconds_since_unix_epoch(now.timestamp() as u64);
        let intermediate_certs: Vec<&[u8]> = intermediate_certs
            .iter()
            .map(|cert| cert.0.as_slice())
            .collect();

        end_entity_certificate.verify_is_valid_tls_server_cert(
            SUPPORTED_SIG_ALGS,
            &TLSServerTrustAnchors(&trust_anchors),
            &intermediate_certs,
            time,
        )
    }

    /// Verifies attestation report
    fn verify_attestation_report(
        &self,
        attestation_report: &[u8],
        public_key: &[u8],
        now: DateTime<Utc>,
    ) -> Result<Quote, EnclaveCertVerifierError> {
        let attestation_report: AttestationReport = serde_json::from_slice(attestation_report)
            .map_err(EnclaveCertVerifierError::AttestationReportParsingError)?;
        let signing_certificate_chain = certs(&mut attestation_report.signing_cert.as_ref())
            .map_err(|_| {
                EnclaveCertVerifierError::AttestationReportSigningCertificateChainParsingError
            })?;
        let signing_cert = get_end_entity_certificate(&signing_certificate_chain)?;

        self.verify_end_entity_certificate(&signing_cert, &signing_certificate_chain[1..], now)
            .map_err(|webpki_error| {
                EnclaveCertVerifierError::AttestationReportSigningCertificateVerificationError(
                    webpki_error,
                )
            })?;
        signing_cert.verify_signature(
            &RSA_PKCS1_2048_8192_SHA256,
            &attestation_report.body,
            &attestation_report.signature,
        )?;
        self.verify_attestation_report_body(&attestation_report.body, public_key, now)
    }

    fn verify_attestation_report_body(
        &self,
        attestation_report_body: &[u8],
        public_key: &[u8],
        now: DateTime<Utc>,
    ) -> Result<Quote, EnclaveCertVerifierError> {
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
        let has_correct_len = public_key.len() == 65;
        let is_uncompressed = public_key[0] == 4;
        let pubkey_matches = public_key[1..] == quote.report_body.report_data[..];
        if !has_correct_len || !is_uncompressed || !pubkey_matches {
            return Err(EnclaveCertVerifierError::PublicKeyMismatch);
        }

        if let Some(ref enclave_info) = self.enclave_info {
            if enclave_info.mr_signer != quote.report_body.measurement.mr_signer {
                return Err(EnclaveCertVerifierError::MeasurementMismatch);
            }

            // SVN verification: https://github.com/crypto-com/thaler-docs/blob/master/docs/modules/tdbe.md#svn-verification--compilation-order
            match (
                enclave_info.isv_svn,
                enclave_info.mr_enclave,
                enclave_info.previous_mr_enclave,
            ) {
                // Case 0: If `mr_enclave` is `None`, which means that we don't have to verify
                // MRENCLAVE values (for `ClientCertiVerifier` for two-way attested TLS stream
                // between different enclaves).
                (isv_svn, None, _) if isv_svn == quote.report_body.isv_svn => Ok(()),
                // Case 1: If `isv_svn` is the same, then `mr_enclave` should be the same
                (isv_svn, Some(mr_enclave), _)
                    if isv_svn == quote.report_body.isv_svn
                        && mr_enclave == quote.report_body.measurement.mr_enclave =>
                {
                    Ok(())
                }
                // Case 2: If `isv_svn` is the previous version, then `mr_enclave` should be same
                // as previous version
                //
                // Enclaves are allowed to connect to previous version for supporting upgrades:
                // - Temporal aspect should be checked/configured by the caller
                // - When older version is not allowed, caller can set `previous_mr_enclave` as `None`)
                (isv_svn, _, Some(previous_mr_enclave))
                    if isv_svn - 1 == quote.report_body.isv_svn
                        && previous_mr_enclave == quote.report_body.measurement.mr_enclave =>
                {
                    Ok(())
                }
                _ => Err(EnclaveCertVerifierError::MeasurementMismatch),
            }?
        }

        Ok(quote)
    }

    /// Converts enclave certificate verifier into client config expected by `rustls`
    pub fn into_client_config(self) -> Result<ClientConfig, EnclaveCertVerifierError> {
        match self.enclave_info {
            None => Err(EnclaveCertVerifierError::MissingEnclaveInfo),
            Some(ref enclave_info) => match enclave_info.mr_enclave {
                Some(_) => Ok(()),
                None => Err(EnclaveCertVerifierError::MissingMrenclave),
            },
        }?;

        let mut config = ClientConfig::new();
        config.dangerous().set_certificate_verifier(Arc::new(self));
        config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
        Ok(config)
    }

    /// Converts enclave certificate verifier into server config (configures current verifier as
    /// client certificate verifier, i.e., the client should also present a valid certificate with
    /// attestation report) expected by `rustls`
    pub fn into_client_verifying_server_config(
        self,
        verify_mr_enclave: bool,
    ) -> Result<ServerConfig, EnclaveCertVerifierError> {
        match self.enclave_info {
            None => Err(EnclaveCertVerifierError::MissingEnclaveInfo),
            Some(ref enclave_info) => {
                if verify_mr_enclave {
                    match enclave_info.mr_enclave {
                        Some(_) => Ok(()),
                        None => Err(EnclaveCertVerifierError::MissingMrenclave),
                    }
                } else {
                    Ok(())
                }
            }
        }?;

        let mut server_config = ServerConfig::new(Arc::new(self));
        server_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
        Ok(server_config)
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
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self, _sni: Option<&DNSName>) -> Option<DistinguishedNames> {
        Some(DistinguishedNames::new())
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
    #[error("Unable to parse attestation report: {0}")]
    AttestationReportParsingError(#[source] serde_json::Error),
    #[error("Unable to parse attestation signing certificate chain")]
    AttestationReportSigningCertificateChainParsingError,
    #[error("Unable to parse attestation signing certificate")]
    AttestationReportSigningCertificateParsingError,
    #[error("Signing certificate verification error: {0}")]
    AttestationReportSigningCertificateVerificationError(#[source] webpki::Error),
    #[error("Enclave certificate expired")]
    CertificateExpired,
    #[error("Enclave certificate not begin yet")]
    CertificateNotBegin,
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
    #[error("Attestation report signing certificate not available")]
    MissingAttestationReportSigningCertificate,
    #[error("Enclave info is not provided for certificate verifier")]
    MissingEnclaveInfo,
    #[error("MRENCLAVE value not provided for certificate verifier")]
    MissingMrenclave,
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

/// Extracted information after success verify attestation certificate
pub struct CertVerifyResult {
    /// Returned public key in enclave certificate. This is in uncompressed raw format (65 bytes).
    pub public_key: [u8; 65],
    /// Enclave quote
    pub quote: Quote,
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use chrono::offset::TimeZone;

    #[test]
    fn test_verify_attestation_report() {
        let ias_ca = include_bytes!(
            "../../../../client-common/src/cipher/AttestationReportSigningCACert.pem"
        );
        let attestation_report = include_bytes!("../test/valid_attestation_report.json");
        let report_data = base64::decode("1g+Nvsow2LXbrJVq/8YS5wMUd+GTeOkBegUmnGtcfyLSS0qP6ufwO2HEDV70O4W/tFDx57tziaOWd6OJjenAeg==").unwrap();
        let public_key = &[&[4], report_data.as_slice()].concat();

        let verifier_config = EnclaveCertVerifierConfig {
            signing_ca_cert_pem: ias_ca.to_vec().into(),
            valid_enclave_quote_statuses: vec![
                "OK".into(),
                "CONFIGURATION_AND_SW_HARDENING_NEEDED".into(),
            ]
            .into(),
            report_validity_secs: 86400,
            enclave_info: None,
        };
        let verifier = EnclaveCertVerifier::new(verifier_config).unwrap();
        let now = Utc.timestamp(1594612800, 0);
        let result = verifier.verify_attestation_report(attestation_report, public_key, now);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_attestation_report_attestation_report_parsing_error() {
        let ias_ca = include_bytes!(
            "../../../../client-common/src/cipher/AttestationReportSigningCACert.pem"
        );
        let attestation_report = &include_bytes!("../test/valid_attestation_report.json")[2..];
        let report_data = base64::decode("1g+Nvsow2LXbrJVq/8YS5wMUd+GTeOkBegUmnGtcfyLSS0qP6ufwO2HEDV70O4W/tFDx57tziaOWd6OJjenAeg==").unwrap();
        let public_key = &[&[4], report_data.as_slice()].concat();

        let verifier_config = EnclaveCertVerifierConfig {
            signing_ca_cert_pem: ias_ca.to_vec().into(),
            valid_enclave_quote_statuses: vec![
                "OK".into(),
                "CONFIGURATION_AND_SW_HARDENING_NEEDED".into(),
            ]
            .into(),
            report_validity_secs: 86400,
            enclave_info: None,
        };
        let verifier = EnclaveCertVerifier::new(verifier_config).unwrap();
        let now = Utc.timestamp(1594612800, 0);
        let result = verifier.verify_attestation_report(attestation_report, public_key, now);

        assert!(matches!(
            result.unwrap_err(),
            EnclaveCertVerifierError::AttestationReportParsingError(_)
        ));
    }

    #[test]
    fn test_verify_attestation_report_attestation_report_signing_certificate_chain_parsing_error() {
        let ias_ca = include_bytes!(
            "../../../../client-common/src/cipher/AttestationReportSigningCACert.pem"
        );

        let invalid_cert_chain = b"-----BEGIN CERTIFICATE-----\ninvalid cert\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ninvalid cert\n-----END CERTIFICATE-----\n";

        let attestation_report = include_bytes!("../test/valid_attestation_report.json");
        let mut attestation_report: AttestationReport =
            serde_json::from_slice(&attestation_report[..]).unwrap();
        attestation_report.signing_cert = invalid_cert_chain.to_vec();
        let attestation_report = serde_json::to_vec(&attestation_report).unwrap();

        let report_data = base64::decode("1g+Nvsow2LXbrJVq/8YS5wMUd+GTeOkBegUmnGtcfyLSS0qP6ufwO2HEDV70O4W/tFDx57tziaOWd6OJjenAeg==").unwrap();
        let public_key = &[&[4], report_data.as_slice()].concat();

        let verifier_config = EnclaveCertVerifierConfig {
            signing_ca_cert_pem: ias_ca.to_vec().into(),
            valid_enclave_quote_statuses: vec![
                "OK".into(),
                "CONFIGURATION_AND_SW_HARDENING_NEEDED".into(),
            ]
            .into(),
            report_validity_secs: 86400,
            enclave_info: None,
        };
        let verifier = EnclaveCertVerifier::new(verifier_config).unwrap();
        let now = Utc.timestamp(1594612800, 0);
        let result =
            verifier.verify_attestation_report(attestation_report.as_slice(), public_key, now);

        assert!(matches!(
            result.unwrap_err(),
            EnclaveCertVerifierError::AttestationReportSigningCertificateChainParsingError
        ));
    }

    #[test]
    fn test_verify_attestation_report_attestation_report_signing_certificate_parsing_error() {
        let ias_ca = include_bytes!(
            "../../../../client-common/src/cipher/AttestationReportSigningCACert.pem"
        );

        let invalid_cert_chain = b"-----BEGIN CERTIFICATE-----\naW52YWxpZCBjZXJ0\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\naW52YWxpZCBjZXJ0\n-----END CERTIFICATE-----\n";

        let attestation_report = include_bytes!("../test/valid_attestation_report.json");
        let mut attestation_report: AttestationReport =
            serde_json::from_slice(&attestation_report[..]).unwrap();
        attestation_report.signing_cert = invalid_cert_chain.to_vec();
        let attestation_report = serde_json::to_vec(&attestation_report).unwrap();

        let report_data = base64::decode("1g+Nvsow2LXbrJVq/8YS5wMUd+GTeOkBegUmnGtcfyLSS0qP6ufwO2HEDV70O4W/tFDx57tziaOWd6OJjenAeg==").unwrap();
        let public_key = &[&[4], report_data.as_slice()].concat();

        let verifier_config = EnclaveCertVerifierConfig {
            signing_ca_cert_pem: ias_ca.to_vec().into(),
            valid_enclave_quote_statuses: vec![
                "OK".into(),
                "CONFIGURATION_AND_SW_HARDENING_NEEDED".into(),
            ]
            .into(),
            report_validity_secs: 86400,
            enclave_info: None,
        };
        let verifier = EnclaveCertVerifier::new(verifier_config).unwrap();
        let now = Utc.timestamp(1594612800, 0);
        let result =
            verifier.verify_attestation_report(attestation_report.as_slice(), public_key, now);

        assert!(matches!(
            result.unwrap_err(),
            EnclaveCertVerifierError::AttestationReportSigningCertificateParsingError
        ));
    }

    #[test]
    fn test_verify_attestation_report_attestation_report_signing_certificate_verification_error() {
        let ias_ca = include_bytes!(
            "../../../../client-common/src/cipher/AttestationReportSigningCACert.pem"
        );
        let invalid_cert_chain = include_bytes!("../test/self-signed.pem");

        let attestation_report = include_bytes!("../test/valid_attestation_report.json");
        let mut attestation_report: AttestationReport =
            serde_json::from_slice(&attestation_report[..]).unwrap();
        attestation_report.signing_cert = invalid_cert_chain.to_vec();
        let attestation_report = serde_json::to_vec(&attestation_report).unwrap();

        let report_data = base64::decode("1g+Nvsow2LXbrJVq/8YS5wMUd+GTeOkBegUmnGtcfyLSS0qP6ufwO2HEDV70O4W/tFDx57tziaOWd6OJjenAeg==").unwrap();
        let public_key = &[&[4], report_data.as_slice()].concat();

        let verifier_config = EnclaveCertVerifierConfig {
            signing_ca_cert_pem: ias_ca.to_vec().into(),
            valid_enclave_quote_statuses: vec![
                "OK".into(),
                "CONFIGURATION_AND_SW_HARDENING_NEEDED".into(),
            ]
            .into(),
            report_validity_secs: 86400,
            enclave_info: None,
        };
        let verifier = EnclaveCertVerifier::new(verifier_config).unwrap();
        let now = Utc.timestamp(1594612800, 0);
        let result =
            verifier.verify_attestation_report(attestation_report.as_slice(), public_key, now);

        assert!(matches!(
            result.unwrap_err(),
            EnclaveCertVerifierError::AttestationReportSigningCertificateVerificationError(_)
        ));
    }

    #[test]
    fn test_verify_attestation_report_missing_attestation_report_signing_certificate() {
        let ias_ca = include_bytes!(
            "../../../../client-common/src/cipher/AttestationReportSigningCACert.pem"
        );

        let attestation_report = include_bytes!("../test/valid_attestation_report.json");
        let mut attestation_report: AttestationReport =
            serde_json::from_slice(&attestation_report[..]).unwrap();
        attestation_report.signing_cert = Vec::new();
        let attestation_report = serde_json::to_vec(&attestation_report).unwrap();

        let report_data = base64::decode("1g+Nvsow2LXbrJVq/8YS5wMUd+GTeOkBegUmnGtcfyLSS0qP6ufwO2HEDV70O4W/tFDx57tziaOWd6OJjenAeg==").unwrap();
        let public_key = &[&[4], report_data.as_slice()].concat();

        let verifier_config = EnclaveCertVerifierConfig {
            signing_ca_cert_pem: ias_ca.to_vec().into(),
            valid_enclave_quote_statuses: vec![
                "OK".into(),
                "CONFIGURATION_AND_SW_HARDENING_NEEDED".into(),
            ]
            .into(),
            report_validity_secs: 86400,
            enclave_info: None,
        };
        let verifier = EnclaveCertVerifier::new(verifier_config).unwrap();
        let now = Utc.timestamp(1594612800, 0);
        let result =
            verifier.verify_attestation_report(attestation_report.as_slice(), public_key, now);

        assert!(matches!(
            result.unwrap_err(),
            EnclaveCertVerifierError::MissingAttestationReportSigningCertificate
        ));
    }

    #[test]
    fn test_verify_attestation_report_public_key_mismatch() {
        let ias_ca = include_bytes!(
            "../../../../client-common/src/cipher/AttestationReportSigningCACert.pem"
        );
        let attestation_report = include_bytes!("../test/valid_attestation_report.json");
        let report_data = base64::decode("1g+Nvsow2LXbrJVq/8YS5wMUd+GTeOkBegUmnGtcfyLSS0qP6ufwO2HEDV70O4W/tFDx67tziaOWd6OJjenAeg==").unwrap();
        let public_key = &[&[4], report_data.as_slice()].concat();

        let verifier_config = EnclaveCertVerifierConfig {
            signing_ca_cert_pem: ias_ca.to_vec().into(),
            valid_enclave_quote_statuses: vec![
                "OK".into(),
                "CONFIGURATION_AND_SW_HARDENING_NEEDED".into(),
            ]
            .into(),
            report_validity_secs: 86400,
            enclave_info: None,
        };
        let verifier = EnclaveCertVerifier::new(verifier_config).unwrap();
        let now = Utc.timestamp(1594612800, 0);
        let result = verifier.verify_attestation_report(attestation_report, public_key, now);

        assert!(matches!(
            result.unwrap_err(),
            EnclaveCertVerifierError::PublicKeyMismatch
        ));
    }
}
