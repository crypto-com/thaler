use crate::common::{hash256, Timespec, HASH_SIZE_256};
use crate::init::address::RedeemAddress;
use crate::init::coin::Coin;
use crate::tx::data::input::TxoPointer;
use crate::tx::data::output::TxOut;
use crate::tx::witness::{tree::RawSignature, EcdsaSignature};
use blake2::Blake2s;
use parity_codec::{Decode, Encode, Input, Output};
use secp256k1::{RecoverableSignature, RecoveryId};
use serde::{Deserialize, Serialize};
use std::fmt;

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

/// attributes in account-related transactions
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AccountOpAttributes {
    pub chain_hex_id: [u8; 1],
    // TODO: Other attributes?
}

/// takes UTXOs inputs, deposits them in the specified account's bonded amount - fee
/// (updates account's bonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct DepositBondTx {
    pub inputs: Vec<TxoPointer>,
    pub to_account: RedeemAddress,
    pub value: Coin,
    pub attributes: AccountOpAttributes,
}

impl fmt::Display for DepositBondTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for input in self.inputs.iter() {
            writeln!(f, "-> {}", input)?;
        }
        writeln!(f, "   {} {} (bonded) ->", self.to_account, self.value)?;
        write!(f, "")
    }
}

/// updates the account (TODO: implicit from the witness?) by moving some of the bonded amount - fee into unbonded,
/// and setting the unbonded_from to last_block_time+min_unbonding_time (network parameter)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct UnbondTx {
    pub value: Coin,
    pub nonce: Nonce,
    pub attributes: AccountOpAttributes,
}

impl fmt::Display for UnbondTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "unbonded: {} (nonce: {})", self.value, self.nonce)?;
        write!(f, "")
    }
}

/// takes the account (TODO: implicit from the witness?) and creates UTXOs
/// (update's account's unbonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct WithdrawUnbondedTx {
    pub value: Coin,
    pub nonce: Nonce,
    pub outputs: Vec<TxOut>,
    pub attributes: AccountOpAttributes,
}

impl fmt::Display for WithdrawUnbondedTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-> {} (unbonded) (nonce: {})", self.value, self.nonce)?;
        for output in self.outputs.iter() {
            writeln!(f, "   {} ->", output)?;
        }
        write!(f, "")
    }
}

/// A witness for account operations
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountOpWitness(EcdsaSignature);

impl Encode for AccountOpWitness {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        let (recovery_id, serialized_sig) = self.0.serialize_compact();
        // recovery_id is one of 0 | 1 | 2 | 3
        let rid = recovery_id.to_i32() as u8;
        dest.push_byte(rid);
        serialized_sig.encode_to(dest);
    }
}

impl Decode for AccountOpWitness {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let rid: u8 = input.read_byte()?;
        let raw_sig = RawSignature::decode(input)?;
        let recovery_id = RecoveryId::from_i32(i32::from(rid)).ok()?;
        let sig = RecoverableSignature::from_compact(&raw_sig, recovery_id).ok()?;
        Some(AccountOpWitness(sig))
    }
}
