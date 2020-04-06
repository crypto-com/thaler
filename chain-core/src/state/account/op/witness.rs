use crate::tx::witness::{tree::RawSignature, EcdsaSignature};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Serialize};

/// A witness for StakedState operations
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub enum StakedStateOpWitness {
    BasicRedeem(EcdsaSignature),
}

impl StakedStateOpWitness {
    pub fn new(sig: EcdsaSignature) -> Self {
        StakedStateOpWitness::BasicRedeem(sig)
    }
}

impl Encode for StakedStateOpWitness {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        match *self {
            StakedStateOpWitness::BasicRedeem(ref sig) => {
                dest.push_byte(0);
                let (recovery_id, serialized_sig) = sig.serialize_compact();
                // recovery_id is one of 0 | 1 | 2 | 3
                let rid = recovery_id.to_i32() as u8;
                dest.push_byte(rid);
                serialized_sig.encode_to(dest);
            }
        }
    }

    fn size_hint(&self) -> usize {
        match self {
            StakedStateOpWitness::BasicRedeem(_) => 66,
        }
    }
}

impl Decode for StakedStateOpWitness {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let tag = input.read_byte()?;
        match tag {
            0 => {
                let rid: u8 = input.read_byte()?;
                let raw_sig = RawSignature::decode(input)?;
                let recovery_id = RecoveryId::from_i32(i32::from(rid))
                    .map_err(|_| Error::from("Unable to parse recovery ID"))?;
                let sig = RecoverableSignature::from_compact(&raw_sig, recovery_id)
                    .map_err(|_| Error::from("Unable to create recoverable signature"))?;
                Ok(StakedStateOpWitness::BasicRedeem(sig))
            }
            _ => Err(Error::from("Invalid tag")),
        }
    }
}
