use digest::Digest;

/// Generic merkle tree
pub mod merkle;

/// Size in bytes of a 256-bit hash
pub const HASH_SIZE_256: usize = 32;

/// Calculates 256-bit crypto hash
pub fn hash256<D: Digest>(data: &[u8]) -> H256 {
    let mut hasher = D::new();
    hasher.input(data);
    let mut out = [0u8; HASH_SIZE_256];
    out.copy_from_slice(&hasher.result()[..]);
    out
}

/// Seconds since UNIX epoch
pub type Timespec = i64;

pub type H256 = [u8; HASH_SIZE_256];
pub type H264 = [u8; HASH_SIZE_256 + 1];
pub type H512 = [u8; HASH_SIZE_256 * 2];
