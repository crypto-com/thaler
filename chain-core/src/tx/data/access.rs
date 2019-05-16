use parity_codec::{Decode, Encode, Input, Output};
use parity_codec_derive::{Decode, Encode};
use secp256k1::key::PublicKey;
use serde::{Deserialize, Serialize};

use crate::tx::witness::tree::RawPubkey;

/// What can be access in TX -- TODO: revisit when enforced by HW encryption / enclaves
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum TxAccess {
    AllData,
    Output(usize),
    // TODO: other components?
    // TODO: TX ID could be computed as a root of a merkle tree from different TX components?
}

impl Default for TxAccess {
    fn default() -> Self {
        TxAccess::AllData
    }
}

/// Specifies who can access what -- TODO: revisit when enforced by HW encryption / enclaves
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TxAccessPolicy {
    pub view_key: PublicKey,
    pub access: TxAccess,
}

impl Encode for TxAccessPolicy {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        dest.push_byte(0);
        dest.push_byte(2);
        let vk: RawPubkey = self.view_key.serialize().into();
        vk.encode_to(dest);
        self.access.encode_to(dest);
    }
}

impl Decode for TxAccessPolicy {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let tag = input.read_byte()?;
        let constructor_len = input.read_byte()?;
        match (tag, constructor_len) {
            (0, 2) => {
                let rawkey = RawPubkey::decode(input)?;
                let view_key = PublicKey::from_slice(rawkey.as_bytes()).ok()?;
                let access = TxAccess::decode(input)?;
                Some(TxAccessPolicy::new(view_key, access))
            }
            _ => None,
        }
    }
}

impl TxAccessPolicy {
    /// creates tx access policy
    pub fn new(view_key: PublicKey, access: TxAccess) -> Self {
        TxAccessPolicy { view_key, access }
    }
}
