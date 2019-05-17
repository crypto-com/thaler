use crate::common::{hash256, Timespec, HASH_SIZE_256};
use crate::init::address::RedeemAddress;
use crate::init::coin::Coin;
use blake2::Blake2s;
use parity_codec_derive::{Decode, Encode};

/// reference counter in the sparse patricia merkle tree/trie
pub type Count = u64;

/// account state update counter
pub type Nonce = u64;

/// represents the account state (involved in staking)
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct Account {
    pub nonce: Nonce,
    pub bonded: Coin,
    pub unbonded: Coin,
    pub unbonded_from: Timespec,
    pub address: RedeemAddress,
    // TODO: slashing + jailing
}

impl Default for Account {
    fn default() -> Self {
        Account::new(0, Coin::zero(), Coin::zero(), 0, RedeemAddress::default())
    }
}

impl Account {
    pub fn new(
        nonce: Nonce,
        bonded: Coin,
        unbonded: Coin,
        unbonded_from: Timespec,
        address: RedeemAddress,
    ) -> Self {
        Account {
            nonce,
            bonded,
            unbonded,
            unbonded_from,
            address,
        }
    }

    /// the tree used in account storage db has a hardcoded 32-byte keys,
    /// this computes a key as blake2s(account.address) where
    /// the account address itself is ETH-style address (20 bytes from keccak hash of public key)
    pub fn key(&self) -> [u8; HASH_SIZE_256] {
        hash256::<Blake2s>(&self.address)
    }
}
