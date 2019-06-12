/// data types related to account operations
pub mod account;
/// data types related to working with Tendermint
pub mod tendermint;

use crate::common::{hash256, H256};
use crate::init::address::RedeemAddress;
use crate::init::coin::Coin;
use blake2::Blake2s;
use parity_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use tendermint::{BlockHeight, TendermintValidatorPubKey};

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

/// holds state about a node responsible for transaction validation / block signing and service node whitelist management
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct CouncilNode {
    // account with the required staked amount
    pub staking_account_address: RedeemAddress,
    // Tendermint consensus validator-associated public key
    pub consensus_pubkey: TendermintValidatorPubKey,
    // update counter
    pub nonce: usize,
    // TODO: public keys / addresses for other operations
}

impl CouncilNode {
    pub fn new(
        staking_account_address: RedeemAddress,
        consensus_pubkey: TendermintValidatorPubKey,
    ) -> Self {
        CouncilNode {
            staking_account_address,
            consensus_pubkey,
            nonce: 0,
        }
    }
}
