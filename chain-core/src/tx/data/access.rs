use crate::tx::witness::tree::RawPubkey;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use secp256k1::key::PublicKey;

/// What can be access in TX -- TODO: revisit when enforced by HW encryption / enclaves
#[derive(Debug, PartialEq, Eq, Clone)]
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

impl Encodable for TxAccess {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            TxAccess::AllData => {
                s.begin_list(1).append(&0u8);
            }
            TxAccess::Output(index) => {
                s.begin_list(2).append(&1u8).append(index);
            }
        }
    }
}

impl Decodable for TxAccess {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let item_count = rlp.item_count()?;
        if !(item_count >= 1 && item_count <= 2) {
            return Err(DecoderError::Custom(
                "Cannot decode a transaction access specification",
            ));
        }
        let type_tag: u8 = rlp.val_at(0)?;
        match (type_tag, item_count) {
            (0, 1) => Ok(TxAccess::AllData),
            (1, 2) => {
                let index = rlp.val_at(1)?;
                Ok(TxAccess::Output(index))
            }
            _ => Err(DecoderError::Custom(
                "Unknown transaction access specification type",
            )),
        }
    }
}

/// Specifies who can access what -- TODO: revisit when enforced by HW encryption / enclaves
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxAccessPolicy {
    pub view_key: PublicKey,
    pub access: TxAccess,
}

impl TxAccessPolicy {
    /// creates tx access policy
    pub fn new(view_key: PublicKey, access: TxAccess) -> Self {
        TxAccessPolicy { view_key, access }
    }
}

impl Encodable for TxAccessPolicy {
    fn rlp_append(&self, s: &mut RlpStream) {
        let vk: RawPubkey = self.view_key.serialize().into();
        s.begin_list(2).append(&vk).append(&self.access);
    }
}

impl Decodable for TxAccessPolicy {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::Custom(
                "Cannot decode a transaction access policy",
            ));
        }
        let rawkey: RawPubkey = rlp.val_at(0)?;
        let view_key = PublicKey::from_slice(&rawkey.as_bytes())
            .map_err(|_| DecoderError::Custom("failed to decode public key"))?;
        let access: TxAccess = rlp.val_at(1)?;
        Ok(TxAccessPolicy::new(view_key, access))
    }
}
