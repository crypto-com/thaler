use crate::common::{hash256, Timespec, HASH_SIZE_256};
use crate::init::address::RedeemAddress;
use crate::init::coin::Coin;
use blake2::Blake2s;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::mem;

/// account state update counter
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Nonce(u64);

impl From<u64> for Nonce {
    fn from(v: u64) -> Self {
        Nonce(v)
    }
}

impl From<Nonce> for u64 {
    fn from(bh: Nonce) -> u64 {
        bh.0
    }
}

impl Encodable for Nonce {
    fn rlp_append(&self, s: &mut RlpStream) {
        let mut bs = [0u8; mem::size_of::<u64>()];
        bs.as_mut()
            .write_u64::<LittleEndian>(self.0)
            .expect("Unable to write Nonce");
        s.encoder().encode_value(&bs[..]);
    }
}

impl Decodable for Nonce {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|mut bytes| match bytes.len() {
            l if l == mem::size_of::<u64>() => {
                let nonce = bytes
                    .read_u64::<LittleEndian>()
                    .map_err(|_| DecoderError::Custom("failed to read u64"))?;
                Ok(Nonce(nonce))
            }
            l if l < mem::size_of::<u64>() => Err(DecoderError::RlpIsTooShort),
            _ => Err(DecoderError::RlpIsTooBig),
        })
    }
}

/// represents the account state (involved in staking)
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Account {
    pub nonce: Nonce,
    pub bonded: Coin,
    pub unbonded: Coin,
    pub unbonded_from: Timespec,
    pub address: RedeemAddress,
    // TODO: slashing + jailing
}

impl Account {
    pub fn new(
        nonce: Nonce,
        bonded: Coin,
        unbonded: Coin,
        unbonded_from: Timespec,
        address: RedeemAddress,
    ) -> Self {
        Account {
            nonce,
            bonded,
            unbonded,
            unbonded_from,
            address,
        }
    }

    /// the tree used in account storage db has a hardcoded 32-byte keys,
    /// this computes a key as blake2s(account.address) where
    /// the account address itself is ETH-style address (20 bytes from keccak hash of public key)
    pub fn key(&self) -> [u8; HASH_SIZE_256] {
        hash256::<Blake2s>(&self.address).0
    }
}

impl Encodable for Account {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5)
            .append(&self.nonce)
            .append(&self.bonded)
            .append(&self.unbonded)
            .append(&self.unbonded_from)
            .append(&self.address);
    }
}

impl Decodable for Account {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 5 {
            return Err(DecoderError::Custom("Cannot decode an account"));
        }
        let nonce: Nonce = rlp.val_at(0)?;
        let bonded: Coin = rlp.val_at(1)?;
        let unbonded: Coin = rlp.val_at(2)?;
        let unbonded_from: Timespec = rlp.val_at(3)?;
        let address: RedeemAddress = rlp.val_at(4)?;
        Ok(Account {
            nonce,
            bonded,
            unbonded,
            unbonded_from,
            address,
        })
    }
}
