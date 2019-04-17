use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};

use crate::common::{H256, H264, H512};

pub type RawPubkey = H264;
pub type RawSignature = H512;

/// Encodes whether a left or right branch was taken
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum MerklePath {
    LFound = 1,
    RFound = 2,
}

/// Contains the path taken + the other branch's hash
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofOp(pub MerklePath, pub H256);

/// TODO: it's a bit wasteful now, perhaps more efficient encoding
/// One option would be (a level up / in TxInWitness) to have a N-bit BitVec that denotes
/// in each bit whether the left or right branch was taken
/// followed by N*32 bytes (N hashes of the other branches)
impl Encodable for ProofOp {
    fn rlp_append(&self, s: &mut RlpStream) {
        let v = self.0 == MerklePath::LFound;
        s.begin_list(2);
        s.append(&v);
        s.append(&self.1);
    }
}

impl Decodable for ProofOp {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let v: bool = rlp.val_at(0)?;
        let p = if v {
            MerklePath::LFound
        } else {
            MerklePath::RFound
        };
        let h: H256 = rlp.val_at(1)?;
        Ok(ProofOp(p, h))
    }
}
