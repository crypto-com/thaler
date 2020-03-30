/// data types related to staked state operations
pub mod account;
/// data types related to working with Tendermint
pub mod tendermint;
/// data types related to council node operations in staked state
pub mod validator;

use parity_scale_codec::{Decode, Encode};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Serialize};
use std::prelude::v1::Vec;

use self::tendermint::BlockHeight;
use crate::common::{MerkleTree, Timespec, H256};
use crate::compute_app_hash;
use crate::init::coin::Coin;
use crate::init::params::NetworkParameters;
use crate::tx::data::TxId;

/// ABCI chain state
#[derive(PartialEq, Debug, Clone, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct ChainState {
    /// root hash of the sparse merkle patricia trie of staking account states
    pub account_root: H256,
    /// last rewards pool state
    pub rewards_pool: RewardsPoolState,
    /// network parameters (fee policy, staking configuration etc.)
    pub network_params: NetworkParameters,
}

impl ChainState {
    pub fn compute_app_hash(&self, txids: Vec<TxId>) -> H256 {
        compute_app_hash(
            &MerkleTree::new(txids),
            &self.account_root,
            &self.rewards_pool,
            &self.network_params,
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
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
    pub tau: u64,
}

impl RewardsPoolState {
    /// retrieves the hash of the current state (currently blake3(scale_code_bytes(rewards_pool_state)))
    pub fn hash(&self) -> H256 {
        blake3::hash(&self.encode()).into()
    }

    pub fn new(genesis_time: Timespec, tau: u64) -> Self {
        RewardsPoolState {
            period_bonus: Coin::zero(),
            last_block_height: 0.into(),
            last_distribution_time: genesis_time,
            minted: Coin::zero(),
            tau,
        }
    }
}
