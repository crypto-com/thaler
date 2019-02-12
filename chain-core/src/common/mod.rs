use digest::Digest;
/// Generic merkle tree
pub mod merkle;
pub const HASH_SIZE_256: usize = 32;

/// Calculates 256-bit crypto hash
pub fn hash256<D: Digest>(data: &[u8]) -> [u8; HASH_SIZE_256] {
    let mut hasher = D::new();
    hasher.input(data);
    let mut out = [0u8; HASH_SIZE_256];
    out.copy_from_slice(&hasher.result()[..]);
    out
}

/// For tagging type names in serialization
pub trait TypeInfo {
    fn type_name() -> &'static str;
}
