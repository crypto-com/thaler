use std::borrow::Cow;

pub struct EnclaveCertVerifierConfig<'a> {
    /// PEM encode bytes containing attestation report signing CA certificate
    pub signing_ca_cert_pem: Cow<'a, [u8]>,
    /// List of all the enclave quote statuses which should be marked as valid
    pub valid_enclave_quote_statuses: Cow<'a, [Cow<'a, str>]>,
    /// Duration for which an attestation report will be considered as valid (in secs)
    pub report_validity_secs: u32,
}
