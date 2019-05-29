pub mod account;

use crate::common::{hash256, H256};
use crate::init::address::RedeemAddress;
use crate::init::coin::Coin;
use crate::tx::witness::tree::RawPubkey;
use blake2::Blake2s;
use parity_codec::{Decode, Encode};
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

/// The protobuf structure currently has "String" to denote the type / length
/// and variable length byte array. In this internal representation,
/// it's desirable to keep it restricted and compact. (TM should be encoding using the compressed form.)
#[derive(Encode, Decode)]
pub enum TendermintValidatorPubKey {
    Ed25519([u8; 32]),
    Secp256k1(RawPubkey),
    // there's also PubKeyMultisigThreshold, but that probably wouldn't be used for individual nodes / validators
    // TODO: some other schemes when they are added in TM?
}

/// holds state about a node responsible for transaction validation / block signing and service node whitelist management
#[derive(Encode, Decode)]
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
