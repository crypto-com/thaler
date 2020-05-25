/// Configuration required by SP for remote attestation
#[derive(Debug)]
pub struct EnclaveRaConfig {
    /// TCP address of SP server for remote attestation
    pub sp_addr: String,
    /// Duration for which a certificate will be valid (in secs)
    pub certificate_validity_secs: u32,
}
