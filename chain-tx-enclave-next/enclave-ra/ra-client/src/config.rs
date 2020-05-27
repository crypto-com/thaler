use std::borrow::Cow;

const IAS_CERT: &[u8] =
    include_bytes!("../../../../client-core/src/cipher/AttestationReportSigningCACert.pem");

#[derive(Clone)]
pub struct EnclaveCertVerifierConfig<'a> {
    /// PEM encode bytes containing attestation report signing CA certificate
    pub signing_ca_cert_pem: Cow<'a, [u8]>,
    /// List of all the enclave quote statuses which should be marked as valid
    pub valid_enclave_quote_statuses: Cow<'a, [Cow<'a, str>]>,
    /// Duration for which an attestation report will be considered as valid (in secs)
    pub report_validity_secs: u32,
    /// Information about the enclave that'll be verifier if present
    pub enclave_info: Option<EnclaveInfo>,
}

impl<'a> EnclaveCertVerifierConfig<'a> {
    pub fn new() -> Self {
        Self {
            signing_ca_cert_pem: IAS_CERT.into(),
            // https://software.intel.com/security-software-guidance/insights/deep-dive-load-value-injection#mitigationguidelines
            valid_enclave_quote_statuses: vec!["OK".into(), "SW_HARDENING_NEEDED".into()].into(),
            report_validity_secs: 86400,
            // FIXME construct enclave_info from env var or config file
            enclave_info: None,
        }
    }
}

impl<'a> Default for EnclaveCertVerifierConfig<'a> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct EnclaveInfo {
    /// 256-bit hash of enclave author's public key
    pub mr_signer: [u8; 32],
    /// 256-bit hash that identifies the code and initial data in enclave
    pub mr_enclave: Option<[u8; 32]>,
    /// CPU security version number
    pub cpu_svn: [u8; 16],
    /// Security version number provided by enclave author
    pub isv_svn: u16,
}
