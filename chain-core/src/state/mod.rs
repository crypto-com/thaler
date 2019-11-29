/// data types related to staked state operations
pub mod account;
/// data types related to working with Tendermint
pub mod tendermint;
/// data types related to council node operations in staked state
pub mod validator;

use blake2::Blake2s;
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use self::tendermint::BlockHeight;
use crate::common::{hash256, Timespec, H256};
use crate::init::coin::Coin;
use crate::tx::fee::Milli;

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RewardsPoolState {
    /// Rewards accumulated in current period
    pub period_bonus: Coin,
    /// last block height that updated it (i64 from Tendermint protobuf)
    pub last_block_height: BlockHeight,
    /// last reward distribution time
    pub last_distribution_time: Timespec,
    /// Record how many coins have been minted, can't exceed the cap
    pub minted: Coin,
    /// Parameter in monetary expansion formula, decayed for each rewards distribution
    pub tau: Milli,
}

impl RewardsPoolState {
    /// retrieves the hash of the current state (currently blake2s(scale_code_bytes(rewards_pool_state)))
    pub fn hash(&self) -> H256 {
        hash256::<Blake2s>(&self.encode())
    }

    pub fn new(genesis_time: Timespec, tau: Milli) -> Self {
        RewardsPoolState {
            period_bonus: Coin::zero(),
            last_block_height: 0,
            last_distribution_time: genesis_time,
            minted: Coin::zero(),
            tau,
        }
    }
}
