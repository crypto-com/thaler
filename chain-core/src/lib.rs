/// Miscellaneous definitions and generic merkle tree
pub mod common;
/// Types mainly related to InitChain command in ABCI
pub mod init;
/// Rewards pool and other stateful structures
pub mod state;
/// Transaction structure types and serialization/deserialization
pub mod tx;

use blake2::Blake2s;
use common::{hash256, MerkleTree, H256};
use state::RewardsPoolState;

/// computes the "global" application hash (used by Tendermint to check consistency + block replaying)
/// currently: app_hash = blake2s(root of valid TX merkle tree || blake2s(scale bytes(rewards pool state)))
/// TODO: it should include the fee policy / network parameters etc. once that becomes changeable
/// MUST/TODO: include node whitelists
pub fn compute_app_hash(
    valid_tx_id_tree: &MerkleTree<H256>,
    account_state_root: &H256,
    reward_pool: &RewardsPoolState,
) -> H256 {
    let valid_tx_part = valid_tx_id_tree.root_hash();
    let rewards_pool_part = reward_pool.hash();
    let mut bs = Vec::new();
    bs.extend(&valid_tx_part);
    bs.extend(&account_state_root[..]);
    bs.extend(&rewards_pool_part);
    hash256::<Blake2s>(&bs)
}
