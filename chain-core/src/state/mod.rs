pub mod account;

use crate::common::{hash256, H256};
use crate::init::coin::Coin;
use blake2::Blake2s;
use parity_codec::Encode;
use parity_codec_derive::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Tendermint block height
/// TODO: u64?
pub type BlockHeight = i64;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct RewardsPoolState {
    /// remaining amount in the pool
    pub remaining: Coin,
    /// last block height that updated it (i64 from Tendermint protobuf)
    pub last_block_height: BlockHeight,
}

impl RewardsPoolState {
    /// retrieves the hash of the current state (currently blake2s(scale_code_bytes(rewards_pool_state)))
    pub fn hash(&self) -> H256 {
        hash256::<Blake2s>(&self.encode())
    }

    pub fn new(remaining: Coin, last_block_height: BlockHeight) -> Self {
        RewardsPoolState {
            remaining,
            last_block_height,
        }
    }
}
