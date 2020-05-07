#![deny(missing_docs, unsafe_code, unstable_features)]
//! The core data types (such as transaction and witness payloads)
#![cfg_attr(all(feature = "mesalock_sgx", not(target_env = "sgx")), no_std)]
#![cfg_attr(
    all(target_env = "sgx", target_vendor = "mesalock"),
    feature(rustc_private)
)]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

/// Miscellaneous definitions and generic merkle tree
pub mod common;
/// Types mainly related to InitChain command in ABCI
pub mod init;
/// Rewards pool and other stateful structures
pub mod state;
/// Transaction structure types and serialization/deserialization
pub mod tx;

use common::{MerkleTree, Timespec, H256};
use init::params::NetworkParameters;
use parity_scale_codec::{Decode, Encode};
use state::tendermint::BlockHeight;
use state::RewardsPoolState;
use tx::fee::Fee;

/// The app version returned in Tendermint "Info" response,
/// included in every header + transaction metadata.
/// It denotes both binary schema and semantics (state machine rules)
/// ref: https://github.com/tendermint/tendermint/blob/master/docs/architecture/adr-016-protocol-versions.md#appversion
/// TODO: upgrades/new version signalling
///
/// version 0 -- 0.4.0 release
/// version 1 -- 0.5.0 release (wire format didn't change, but unbond tx semantics changed: https://github.com/crypto-com/chain/pull/1516)
pub const APP_VERSION: u64 = 1;

/// computes the "global" application hash (used by Tendermint to check consistency + block replaying)
/// currently: app_hash = blake3(root of valid TX merkle tree
/// || root of account/staked state trie || blake3(scale bytes(rewards pool state)) || blake3(scale bytes(network params)))
/// TODO: cache (as many parts remain static)
/// MUST/TODO: include node whitelists
pub fn compute_app_hash(
    valid_tx_id_tree: &MerkleTree<H256>,
    account_state_root: &H256,
    reward_pool: &RewardsPoolState,
    params: &NetworkParameters,
) -> H256 {
    let valid_tx_part = valid_tx_id_tree.root_hash();
    let rewards_pool_part = reward_pool.hash();
    let network_params_part = params.hash();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&valid_tx_part);
    hasher.update(&account_state_root[..]);
    hasher.update(&rewards_pool_part);
    hasher.update(&network_params_part);
    hasher.finalize().into()
}

/// External information needed for TX validation
#[derive(Clone, Copy, Encode, Decode)]
pub struct ChainInfo {
    /// minimal fee computed for the transaction
    pub min_fee_computed: Fee,
    /// network hexamedical ID
    pub chain_hex_id: u8,
    /// block time of current processing block
    pub block_time: Timespec,
    /// height of current processing block
    pub block_height: BlockHeight,
    /// max evidence age in tendermint consensus parameter
    pub max_evidence_age: Timespec,
}

impl ChainInfo {
    /// Get unbonding period, which is the same as max evidence age
    pub fn get_unbonding_period(&self) -> Timespec {
        self.max_evidence_age
    }
}
