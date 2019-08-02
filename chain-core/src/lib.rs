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
use init::coin::Coin;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
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
#[derive(Clone, Copy)]
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

impl Encode for ChainInfo {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.min_fee_computed.to_coin().encode_to(dest);
        dest.push_byte(self.chain_hex_id);
        self.previous_block_time.encode_to(dest);
        self.unbonding_period.encode_to(dest);
    }
}

impl Decode for ChainInfo {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let fee = Coin::decode(input)?;
        let chain_hex_id: u8 = input.read_byte()?;
        let previous_block_time = Timespec::decode(input)?;
        let unbonding_period = u32::decode(input)?;
        Ok(ChainInfo {
            min_fee_computed: Fee::new(fee),
            chain_hex_id,
            previous_block_time,
            unbonding_period,
        })
    }
}
