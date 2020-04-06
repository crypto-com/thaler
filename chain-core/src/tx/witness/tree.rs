use crate::common::{H256, H512};
use parity_scale_codec::{Decode, Encode, EncodeLike, Error, Input, Output};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Serialize};
use std::prelude::v1::Vec;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(not(feature = "mesalock_sgx"), serde(transparent))]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct RawXOnlyPubkey(H256);

impl Encode for RawXOnlyPubkey {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        self.0.encode_to(dest)
    }
    fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }

    fn size_hint(&self) -> usize {
        self.0.size_hint()
    }
}
impl EncodeLike<H256> for RawXOnlyPubkey {}

impl Decode for RawXOnlyPubkey {
    fn decode<DecIn: Input>(input: &mut DecIn) -> Result<Self, Error> {
        let key = H256::decode(input)?;
        Ok(Self(key))
    }
}

impl RawXOnlyPubkey {
    /// Extracts a byte slice containing the entire public key.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for RawXOnlyPubkey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<H256> for RawXOnlyPubkey {
    fn from(h: H256) -> Self {
        RawXOnlyPubkey(h)
    }
}

pub type RawSignature = H512;
