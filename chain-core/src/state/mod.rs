/// data types related to staked state operations
pub mod account;
/// data types related to working with Tendermint
pub mod tendermint;
/// data types related to council node operations in staked state
pub mod validator;

use crate::common::{hash256, H256};
use crate::init::coin::Coin;
use blake2::Blake2s;
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tendermint::BlockHeight;

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
