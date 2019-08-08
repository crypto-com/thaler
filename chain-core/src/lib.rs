#![cfg_attr(all(feature = "mesalock_sgx", not(target_env = "sgx")), no_std)]
#![cfg_attr(
    all(target_env = "sgx", target_vendor = "mesalock"),
    feature(rustc_private)
)]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

use std::prelude::v1::Vec;

/// Miscellaneous definitions and generic merkle tree
pub mod common;
/// Types mainly related to InitChain command in ABCI
pub mod init;
/// Rewards pool and other stateful structures
pub mod state;
/// Transaction structure types and serialization/deserialization
pub mod tx;

use blake2::Blake2s;
use common::{hash256, MerkleTree, Timespec, H256};
use parity_scale_codec::{Decode, Encode};
use state::RewardsPoolState;
use tx::fee::Fee;

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

/// External information needed for TX validation
#[derive(Clone, Copy, Encode, Decode)]
pub struct ChainInfo {
    /// minimal fee computed for the transaction
    pub min_fee_computed: Fee,
    /// network hexamedical ID
    pub chain_hex_id: u8,
    /// time in the previous committed block
    pub previous_block_time: Timespec,
    /// how much time is required to wait until stake state's unbonded amount can be withdrawn
    pub unbonding_period: u32,
}
