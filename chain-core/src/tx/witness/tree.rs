use crate::common::{H256, H512};
use parity_scale_codec::{Decode, Encode};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Serialize};

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(not(feature = "mesalock_sgx"), serde(transparent))]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct RawXOnlyPubkey(H256);

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
