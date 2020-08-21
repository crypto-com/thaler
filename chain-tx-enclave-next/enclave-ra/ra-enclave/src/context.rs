use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use ra_common::{AttestationReport, OID_EXTENSION_ATTESTATION_REPORT};
use ra_sp_client::{SpRaClient, SpRaClientError};
use rcgen::{
    Certificate as RcGenCertificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, SanType, PKCS_ECDSA_P256_SHA256,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{Certificate as RustlsCertificate, PrivateKey};
use sgx_isa::{Report, Targetinfo};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    certificate::Certificate,
    cmac::{Cmac, CmacError},
    config::EnclaveRaConfig,
};
use ra_common::DEFAULT_EXPIRATION_SECS;

/// Wraps all the in-enclave operations required for remote attestation
pub struct EnclaveRaContext {
    certificate: Arc<Mutex<Option<Certificate>>>,
    sp_ra_client: SpRaClient,
    validity_duration: Duration,
    expiration_duration: Duration,
}

impl EnclaveRaContext {
    /// Creates a new enclave remote attestation context
    pub fn new(config: &EnclaveRaConfig) -> Result<Self, EnclaveRaContextError> {
        let sp_ra_client = SpRaClient::connect(&config.sp_addr)?;
        let validity_duration = Duration::seconds(config.certificate_validity_secs.into());
        let expiration_duration = config
            .certificate_expiration_time
            .unwrap_or_else(|| Duration::seconds(DEFAULT_EXPIRATION_SECS));

        Ok(Self {
            certificate: Default::default(),
            sp_ra_client,
            validity_duration,
            expiration_duration,
        })
    }

    /// Returns current certificate. If current certificate is no longer valid, then it creates a new one
    pub fn get_certificate(&self) -> Result<Certificate, EnclaveRaContextError> {
        let mut certificate = self.certificate.lock().unwrap();

        let needs_creating = match *certificate {
            None => true,
            Some(ref certificate) => !certificate.is_valid(self.validity_duration),
        };

        if needs_creating {
            let new_certificate = self.create_certificate();

            match new_certificate {
                Ok(new_certificate) => {
                    log::info!("Successfully created new certificate for remote attestation");
                    *certificate = Some(new_certificate);
                }
                Err(e) => {
                    // If the certificate generation fails, we do not crash and keep using the old certificate
                    // (if available) and client can decide if they want to use the old certificate. Every certificate
                    // has a 90 days valid duration. If certificate creation fails for 90 days, the enclave itself will
                    // not serve any client.
                    log::error!("Failed to create new certificate: {}", e);
                }
            }
        }

        match *certificate {
            Some(ref certificate) => Ok(certificate.clone()),
            None => Err(EnclaveRaContextError::CertificateCreationError),
        }
    }

    /// Generates attestation report for remote attestation
    fn get_attestation_report(
        &self,
        public_key: &[u8],
    ) -> Result<AttestationReport, EnclaveRaContextError> {
        // Get target info from SP server
        let target_info_bytes = self.sp_ra_client.get_target_info()?;
        let target_info = Targetinfo::try_copy_from(&target_info_bytes)
            .ok_or_else(|| EnclaveRaContextError::InvalidTargetInfo)?;

        // Generate enclave report
        let report = self.get_report(&target_info, public_key)?;
        let report_bytes: &[u8] = report.as_ref();

        // Get quote and QE report from SP server
        let nonce = get_random_nonce()?;
        let quote_result = self.sp_ra_client.get_quote(report_bytes.to_vec(), nonce)?;
        let quote = quote_result.quote;
        let qe_report_bytes = quote_result.qe_report;

        // Verify QE report
        let qe_report = Report::try_copy_from(&qe_report_bytes)
            .ok_or_else(|| EnclaveRaContextError::InvalidQeReport)?;
        verify_qe_report(&qe_report, &target_info, &quote, nonce)?;

        // Get attestation report from SP server
        self.sp_ra_client
            .get_attestation_report(quote)
            .map_err(Into::into)
    }

    /// Generates enclave report containing public key of RA-TLS key-pair in user-data
    fn get_report(
        &self,
        target_info: &Targetinfo,
        public_key: &[u8],
    ) -> Result<Report, EnclaveRaContextError> {
        assert_eq!(
            65,
            public_key.len(),
            "Expected raw 65 byte uncompressed public key"
        );
        assert_eq!(
            4, public_key[0],
            "Expected first byte of uncompressed public key to be 4"
        );

        let mut report_data = [0; 64];
        report_data.copy_from_slice(&public_key[1..]);

        Ok(Report::for_target(target_info, &report_data))
    }

    /// Creates new certificate
    fn create_certificate(&self) -> Result<Certificate, EnclaveRaContextError> {
        let certificate_params = self.create_certificate_params()?;

        let private_key = PrivateKey(
            certificate_params
                .key_pair
                .as_ref()
                .ok_or_else(|| EnclaveRaContextError::MissingKeyPair)?
                .serialize_der(),
        );
        let created = certificate_params.not_before;
        let rustls_certificate =
            RustlsCertificate(RcGenCertificate::from_params(certificate_params)?.serialize_der()?);

        Ok(Certificate {
            certificate: rustls_certificate,
            created,
            private_key,
        })
    }

    /// Creates new certificate params
    fn create_certificate_params(&self) -> Result<CertificateParams, EnclaveRaContextError> {
        let mut certificate_params = CertificateParams::default();

        certificate_params.alg = &PKCS_ECDSA_P256_SHA256;

        let current_time = Utc::now();
        // 1 minute offset is to make the keypackage immediately usable, because block time might lag behind the system time
        certificate_params.not_before = current_time - Duration::minutes(1);
        certificate_params.not_after = current_time + self.expiration_duration;

        certificate_params.subject_alt_names =
            vec![SanType::Rfc822Name("security@crypto.com".to_string())];

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::OrganizationName, "Crypto.com");
        distinguished_name.push(DnType::CommonName, "Crypto.com");
        certificate_params.distinguished_name = distinguished_name;

        certificate_params.is_ca = IsCa::SelfSignedOnly;

        let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;

        let attestation_report = self.get_attestation_report(key_pair.public_key_raw())?;
        certificate_params.custom_extensions = vec![CustomExtension::from_oid_content(
            OID_EXTENSION_ATTESTATION_REPORT,
            serde_json::to_vec(&attestation_report)?,
        )];

        certificate_params.key_pair = Some(key_pair);

        Ok(certificate_params)
    }
}

/// Verifies QE report
fn verify_qe_report(
    report: &Report,
    target_info: &Targetinfo,
    quote: &[u8],
    nonce: [u8; 16],
) -> Result<(), EnclaveRaContextError> {
    // Check if the QE report is valid
    verify_report(report)?;

    // Check if the qe_report is produced on the same platform
    if target_info.measurement != report.mrenclave || target_info.attributes != report.attributes {
        return Err(EnclaveRaContextError::InvalidQeReport);
    }

    // Check for replay attacks
    let mut nonce_data = nonce.to_vec();
    nonce_data.extend(quote);
    let hash = sha256(&nonce_data);

    if hash != report.reportdata[..32] {
        return Err(EnclaveRaContextError::InvalidQeReport);
    }

    Ok(())
}

/// Verifies the report
fn verify_report(report: &Report) -> Result<(), EnclaveRaContextError> {
    report
        .verify(|key, mac_data, mac| {
            let cmac = Cmac::new(key);
            cmac.verify(mac_data, mac)
        })
        .map_err(Into::into)
}

/// Creates a random nonce
fn get_random_nonce() -> Result<[u8; 16], EnclaveRaContextError> {
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce)
        .map_err(|_| EnclaveRaContextError::RngError)?;
    Ok(nonce)
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[derive(Debug, Error)]
pub enum EnclaveRaContextError {
    #[error("Unable to create new certificate")]
    CertificateCreationError,
    #[error("CMAC error while verifying report: {0}")]
    CmacError(#[from] CmacError),
    #[error("Invalid target info received from SP server")]
    InvalidTargetInfo,
    #[error("Invalid QE report received from SP server")]
    InvalidQeReport,
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Key pair in certificate parameters not found")]
    MissingKeyPair,
    #[error("Certificate generateion error: {0}")]
    RcGenError(#[from] rcgen::RcgenError),
    #[error("Random number generation error")]
    RngError,
    #[error("SP client error: {0}")]
    SpRaClientError(#[from] SpRaClientError),
}
