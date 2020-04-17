use std::borrow::ToOwned;
use std::fmt;
use std::prelude::v1::{String, Vec};
use std::string::ToString;

use digest::Digest;

/// Fixed point arithmetic
pub mod fixed;
/// Generic merkle tree
mod merkle_tree;

pub use merkle_tree::{MerkleTree, Proof};

/// Size in bytes of a 256-bit hash
pub const HASH_SIZE_256: usize = 32;

/// Calculates 256-bit crypto hash
pub fn hash256<D: Digest>(data: &[u8]) -> H256 {
    let mut hasher = D::new();
    hasher.input(data);
    let mut out = [0u8; HASH_SIZE_256];
    out.copy_from_slice(&hasher.result()[..]);
    out
}

/// Seconds since UNIX epoch
pub type Timespec = u64;

/// 32-byte for keys or hashes etc.
pub type H256 = [u8; HASH_SIZE_256];
/// 33-byte for pubkeys etc.
pub type H264 = [u8; HASH_SIZE_256 + 1];
/// 64-byte for sigs etc.
pub type H512 = [u8; HASH_SIZE_256 * 2];

/// Types of tendermint events created during `deliver_tx` / `end_block`
#[derive(Debug, Clone, Copy)]
pub enum TendermintEventType {
    /// if transaction is valid
    ValidTransactions,
    /// filter for view pub keys
    BlockFilter,
    /// staking account related changes
    StakingChange,
    /// when reward was distributed
    Reward,
}

impl fmt::Display for TendermintEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TendermintEventType::ValidTransactions => write!(f, "valid_txs"),
            TendermintEventType::BlockFilter => write!(f, "block_filter"),
            TendermintEventType::StakingChange => write!(f, "staking_change"),
            TendermintEventType::Reward => write!(f, "reward"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// Attribute key of tendermint events
pub enum TendermintEventKey {
    /// paid fee
    Fee,
    /// transaction identifier (in valid transactions)
    TxId,
    /// bloom filter of view keys
    EthBloom,
    /// affected staking address
    StakingAddress,
    /// staking operation type
    StakingOpType,
    /// staking state difference
    StakingDiff,
    /// staking operation reason
    StakingOpReason,
    /// new coins minted from rewards pool
    CoinMinted,
    /// when state was slashed
    Slash,
}

impl From<TendermintEventKey> for Vec<u8> {
    #[inline]
    fn from(key: TendermintEventKey) -> Vec<u8> {
        key.to_vec()
    }
}

impl PartialEq<TendermintEventKey> for Vec<u8> {
    fn eq(&self, other: &TendermintEventKey) -> bool {
        *self == other.to_vec()
    }
}
impl PartialEq<Vec<u8>> for TendermintEventKey {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.to_vec() == *other
    }
}

impl fmt::Display for TendermintEventKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TendermintEventKey::Fee => write!(f, "fee"),
            TendermintEventKey::TxId => write!(f, "txid"),
            TendermintEventKey::EthBloom => write!(f, "ethbloom"),
            TendermintEventKey::StakingAddress => write!(f, "staking_address"),
            TendermintEventKey::StakingOpType => write!(f, "staking_optype"),
            TendermintEventKey::StakingDiff => write!(f, "staking_diff"),
            TendermintEventKey::StakingOpReason => write!(f, "staking_opreason"),
            TendermintEventKey::CoinMinted => write!(f, "minted"),
            TendermintEventKey::Slash => write!(f, "slash"),
        }
    }
}

impl TendermintEventKey {
    /// to raw bytes
    #[inline]
    pub fn to_vec(self) -> Vec<u8> {
        self.to_string().as_bytes().to_owned()
    }

    /// to base64-encoded string
    #[inline]
    pub fn to_base64_string(self) -> String {
        match self {
            TendermintEventKey::Fee => String::from("ZmVl"),
            TendermintEventKey::TxId => String::from("dHhpZA=="),
            TendermintEventKey::EthBloom => String::from("ZXRoYmxvb20="),
            TendermintEventKey::StakingAddress => String::from("c3Rha2luZ19hZGRyZXNz"),
            TendermintEventKey::StakingOpType => String::from("c3Rha2luZ19vcHR5cGU="),
            TendermintEventKey::StakingDiff => String::from("c3Rha2luZ19kaWZm"),
            TendermintEventKey::StakingOpReason => String::from("c3Rha2luZ19vcHJlYXNvbg=="),
            TendermintEventKey::CoinMinted => String::from("bWludGVk"),
            TendermintEventKey::Slash => String::from("c2xhc2g="),
        }
    }
}
