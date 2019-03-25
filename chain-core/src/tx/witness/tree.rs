use crate::common::{H256, H264, H512};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

pub type RawPubkey = H264;
pub type RawSignature = H512;

/// Encodes whether a left or right branch was taken
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MerklePath {
    LFound = 1,
    RFound = 2,
}

/// Contains the path taken + the other branch's hash
pub type ProofOp = (MerklePath, H256);

impl Encodable for MerklePath {
    fn rlp_append(&self, s: &mut RlpStream) {
        let v = *self == MerklePath::LFound;
        s.append(&v);
    }
}

impl Decodable for MerklePath {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let v: bool = rlp.as_val()?;
        if v {
            Ok(MerklePath::LFound)
        } else {
            Ok(MerklePath::RFound)
        }
    }
}
