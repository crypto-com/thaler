use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use secp256k1::key::PublicKey;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::common::H264;

/// What can be access in TX -- TODO: revisit when enforced by HW encryption / enclaves
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TxAccess {
    AllData,
    // TODO: u16 and Vec size check in Decode implementation
    Output(u64),
    // TODO: other components?
    // TODO: TX ID could be computed as a root of a merkle tree from different TX components?
}

impl Default for TxAccess {
    fn default() -> Self {
        TxAccess::AllData
    }
}

/// Specifies who can access what -- TODO: revisit when enforced by HW encryption / enclaves
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxAccessPolicy {
    pub view_key: PublicKey,
    pub access: TxAccess,
}

impl Encode for TxAccessPolicy {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.view_key.serialize().encode_to(dest);
        self.access.encode_to(dest);
    }

    fn size_hint(&self) -> usize {
        33 + self.access.size_hint()
    }
}

impl Decode for TxAccessPolicy {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let view_key_bytes = H264::decode(input)?;
        let view_key = PublicKey::from_slice(&view_key_bytes)
            .map_err(|_| Error::from("Unable to parse public key"))?;
        let access = TxAccess::decode(input)?;
        Ok(TxAccessPolicy::new(view_key, access))
    }
}

impl TxAccessPolicy {
    /// creates tx access policy
    pub fn new(view_key: PublicKey, access: TxAccess) -> Self {
        TxAccessPolicy { view_key, access }
    }
}
