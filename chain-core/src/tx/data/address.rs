use crate::common::H256;
use crate::init::address::RedeemAddress;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::fmt;

/// TODO: opaque types?
type TreeRoot = H256;

/// Currently, only Ethereum-style redeem address + MAST of Or operations (records the root).
/// TODO: HD-addresses?
#[derive(Debug, PartialEq, PartialOrd, Ord, Hash, Eq, Clone)]
pub enum ExtendedAddr {
    BasicRedeem(RedeemAddress),
    OrTree(TreeRoot),
}

impl fmt::Display for ExtendedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtendedAddr::BasicRedeem(addr) => write!(f, "0x{}", addr),
            ExtendedAddr::OrTree(hash) => write!(f, "TODO (base58) 0x{}", hex::encode(hash)),
        }
    }
}

impl Encodable for ExtendedAddr {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            ExtendedAddr::BasicRedeem(addr) => {
                s.begin_list(2).append(&0u8).append(addr);
            }
            ExtendedAddr::OrTree(th) => {
                s.begin_list(2).append(&1u8).append(th);
            }
        }
    }
}

impl Decodable for ExtendedAddr {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::Custom(
                "Cannot decode an extended address structure",
            ));
        }
        let type_tag: u8 = rlp.val_at(0)?;
        match type_tag {
            0 => {
                let addr: RedeemAddress = rlp.val_at(1)?;
                Ok(ExtendedAddr::BasicRedeem(addr))
            }
            1 => {
                let th: TreeRoot = rlp.val_at(1)?;
                Ok(ExtendedAddr::OrTree(th))
            }
            _ => Err(DecoderError::Custom("Unknown transaction type")),
        }
    }
}
