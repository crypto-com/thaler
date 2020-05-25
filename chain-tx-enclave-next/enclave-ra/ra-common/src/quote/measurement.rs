/// Measurement of the code and data in the enclave along with the enclave author's identity
#[derive(Debug)]
pub struct Measurement {
    /// 256-bit hash of the enclave author's public key. This serves as the identity of the enclave author. The result
    /// is that those enclaves which have been authenticated with the same key shall have the same value placed in
    /// `mr_signer`.
    pub mr_signer: [u8; 32],
    /// A single 256-bit hash that identifies the code and initial data to be placed inside the enclave, the expected
    /// order and position in which they are to be placed, and the security properties of those pages. A change in any
    /// of these variables will result in a different measurement.
    pub mr_enclave: [u8; 32],
}
