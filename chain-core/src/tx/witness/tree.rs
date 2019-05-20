use parity_codec::{Decode, Encode, Input, Output};
use serde::{Deserialize, Serialize};

use crate::common::{H256, H264, H512};

/// there's no [T; 33] / [u8; 33] impl in parity-codec :/
pub struct RawPubkey(H264);

impl From<H264> for RawPubkey {
    fn from(h: H264) -> Self {
        RawPubkey(h)
    }
}

impl RawPubkey {
    /// Extracts a byte slice containing the entire public key.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Encode for RawPubkey {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        for item in self.0.iter() {
            dest.push_byte(*item);
        }
    }
}

impl Decode for RawPubkey {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let mut r = [0u8; 33];
        for item in (&mut r).iter_mut() {
            *item = input.read_byte()?;
        }
        Some(RawPubkey(r))
    }
}

pub type RawSignature = H512;

/// Encodes whether a left or right branch was taken
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub enum MerklePath {
    LFound = 1,
    RFound = 2,
}

/// Contains the path taken + the other branch's hash
/// TODO: it's a probably bit wasteful encoding now, perhaps more efficient encoding
/// One option would be (a level up / in TxInWitness) to have a N-bit BitVec that denotes
/// in each bit whether the left or right branch was taken
/// followed by N*32 bytes (N hashes of the other branches)
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ProofOp(pub MerklePath, pub H256);
