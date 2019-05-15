pub mod account;

use std::mem;

use crate::common::{hash256, H256};
use crate::init::coin::Coin;
use blake2::Blake2s;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};

/// Tendermint block height
/// TODO: check > 0 ?
#[derive(Debug, PartialEq, Eq, Clone, Copy, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlockHeight(i64);

impl From<i64> for BlockHeight {
    fn from(v: i64) -> Self {
        BlockHeight(v)
    }
}

impl From<BlockHeight> for i64 {
    fn from(bh: BlockHeight) -> i64 {
        bh.0
    }
}

impl Encodable for BlockHeight {
    fn rlp_append(&self, s: &mut RlpStream) {
        let mut bs = [0u8; mem::size_of::<i64>()];
        bs.as_mut()
            .write_i64::<LittleEndian>(self.0)
            .expect("Unable to write BlockHeight");
        s.encoder().encode_value(&bs[..]);
    }
}

impl Decodable for BlockHeight {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|mut bytes| match bytes.len() {
            l if l == mem::size_of::<i64>() => {
                let r = bytes
                    .read_i64::<LittleEndian>()
                    .map_err(|_| DecoderError::Custom("failed to read i64"))?;
                Ok(BlockHeight(r))
            }
            l if l < mem::size_of::<i64>() => Err(DecoderError::RlpIsTooShort),
            _ => Err(DecoderError::RlpIsTooBig),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct RewardsPoolState {
    /// remaining amount in the pool
    pub remaining: Coin,
    /// last block height that updated it (i64 from Tendermint protobuf)
    pub last_block_height: BlockHeight,
}

impl Encodable for RewardsPoolState {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&self.remaining)
            .append(&self.last_block_height);
    }
}

impl Decodable for RewardsPoolState {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::Custom("Cannot decode a rewards pool state"));
        }
        let remaining: Coin = rlp.val_at(0)?;
        let last_block_height: BlockHeight = rlp.val_at(1)?;
        Ok(RewardsPoolState {
            remaining,
            last_block_height,
        })
    }
}

impl RewardsPoolState {
    /// retrieves the hash of the current state (currently blake2s(rlp_bytes(rewards_pool_state)))
    pub fn hash(&self) -> H256 {
        hash256::<Blake2s>(&self.rlp_bytes())
    }

    pub fn new(remaining: Coin, last_block_height: BlockHeight) -> Self {
        RewardsPoolState {
            remaining,
            last_block_height,
        }
    }
}
