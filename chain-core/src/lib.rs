/// Miscellaneous definitions and generic merkle tree
#[macro_use]
pub mod common;
/// Types mainly related to InitChain command in ABCI
pub mod init;
/// Rewards pool and other stateful structures
pub mod state;
/// Transaction structure types and serialization/deserialization
pub mod tx;

use blake2::Blake2s;
use common::{hash256, merkle::MerkleTree, H256};
use state::RewardsPoolState;

pub fn compute_app_hash(valid_tx_id_tree: &MerkleTree, reward_pool: &RewardsPoolState) -> H256 {
    let valid_tx_part = valid_tx_id_tree.get_root_hash();
    let rewards_pool_part = reward_pool.hash();
    let mut bs = Vec::new();
    bs.extend(valid_tx_part.as_bytes());
    bs.extend(rewards_pool_part.as_bytes());
    hash256::<Blake2s>(&bs)
}
