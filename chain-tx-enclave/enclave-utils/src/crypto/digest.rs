use ring::digest::{digest, SHA256};
use std::convert::TryInto;

const SHA256DIGEST_LEN: usize = 32;
pub type Sha256Digest = [u8; SHA256DIGEST_LEN];

pub fn sha256(data: &[u8]) -> Sha256Digest {
    let digest = digest(&SHA256, data);
    digest.as_ref().try_into().unwrap()
}
