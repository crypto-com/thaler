use std::borrow::Cow;

use sgx_isa::Report;

const IAS_CERT: &[u8] =
    include_bytes!("../../../../client-common/src/cipher/AttestationReportSigningCACert.pem");

/// Default time for which an attestation report will be considered as valid. Currently, it is set
/// to 90 days as recommended in Intel SGX documentation.
///
/// TODO: Some tests with expiration, constructions with smaller validity.
const DEFAULT_VALIDITY_SECS: u32 = 86400;

#[derive(Clone)]
pub struct EnclaveCertVerifierConfig<'a> {
    /// PEM encode bytes containing attestation report signing CA certificate
    pub signing_ca_cert_pem: Cow<'a, [u8]>,
    /// List of all the enclave quote statuses which should be marked as valid
    pub valid_enclave_quote_statuses: Cow<'a, [Cow<'a, str>]>,
    /// Duration for which an attestation report will be considered as valid (in secs)
    pub report_validity_secs: u32,
    /// Information about the enclave that'll be verifier if present -- TODO: make non-optional?
    pub enclave_info: Option<EnclaveInfo>,
}

impl<'a> EnclaveCertVerifierConfig<'a> {
    /// Creates a new instance of enclave certificate verifier config with default values
    pub fn new() -> Self {
        Self {
            signing_ca_cert_pem: IAS_CERT.into(),
            // https://software.intel.com/security-software-guidance/insights/deep-dive-load-value-injection#mitigationguidelines
            valid_enclave_quote_statuses: vec!["OK".into(), "SW_HARDENING_NEEDED".into()].into(),
            report_validity_secs: DEFAULT_VALIDITY_SECS,
            enclave_info: None,
        }
    }

    /// Creates a new instance of enclave certificate verifier config with given enclave info
    pub fn new_with_enclave_info(enclave_info: EnclaveInfo) -> Self {
        let mut verifier_config = Self::new();
        verifier_config.enclave_info = Some(enclave_info);
        verifier_config
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
    ///
    /// # Note
    ///
    /// - This value will be `Some` for `ServerCertVerifier` in any type of attested connection.
    /// - This value will be `None` for `ClientCertVerifier` in two-way mutually attested TLS
    ///   stream between different enclaves.
    /// - This value will be `Some()` for `ClientCertVerifier` in two-way mutually attested TLS
    ///   stream between same enclaves.
    /// - `EnclaveInfo` will be `None` for `ClientCertVerifier` in one-way attested TLS stream.
    pub mr_enclave: Option<[u8; 32]>,
    /// `mr_enclave` corresponding to previous `isv_svn`, i.e., `isv_svn - 1`
    pub previous_mr_enclave: Option<[u8; 32]>,
    /// CPU security version number
    pub cpu_svn: [u8; 16],
    /// Security version number provided by enclave author
    pub isv_svn: u16,
    /// Product ID of enclave
    pub isv_prod_id: u16,
    /// Attributes of the enclave, for example, whether the enclave is running in debug mode
    pub attributes: [u8; 16],
}

impl EnclaveInfo {
    /// Creates an `EncalveInfo` object from enclave `Report`
    pub fn from_report(report: Report, previous_mr_enclave: Option<[u8; 32]>) -> Self {
        let mut attributes = [0; 16];

        // This will never panic because `UNPADDED_SIZE` for attributes in `Report` is 16 bytes. See
        // here: https://github.com/fortanix/rust-sgx/blob/master/sgx-isa/src/lib.rs#L385
        attributes.copy_from_slice(&report.attributes.as_ref());

        Self {
            mr_signer: report.mrsigner,
            mr_enclave: Some(report.mrenclave),
            previous_mr_enclave,
            cpu_svn: report.cpusvn,
            isv_svn: report.isvsvn,
            isv_prod_id: report.isvprodid,
            attributes,
        }
    }
}
