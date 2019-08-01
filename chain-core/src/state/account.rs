use crate::common::{hash256, Timespec, HASH_SIZE_256};
use crate::init::address::RedeemAddress;
use crate::init::coin::Coin;
use crate::init::coin::{sum_coins, CoinError};
use crate::tx::data::attribute::TxAttributes;
use crate::tx::data::input::TxoPointer;
use crate::tx::data::output::TxOut;
use crate::tx::witness::{tree::RawSignature, EcdsaSignature};
use crate::tx::TransactionId;
use blake2::Blake2s;
use parity_codec::{Decode, Encode, Input, Output};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::prelude::v1::Vec;
use std::str::FromStr;
// TODO: switch to normal signatures + explicit public key
use crate::init::address::ErrorAddress;
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use std::convert::{From, TryFrom};
use std::fmt;

/// reference counter in the sparse patricia merkle tree/trie
pub type Count = u64;

/// StakedState update counter
pub type Nonce = u64;

/// StakedState address type
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum StakedStateAddress {
    BasicRedeem(RedeemAddress),
}

impl TryFrom<&[u8]> for StakedStateAddress {
    type Error = ErrorAddress;

    fn try_from(c: &[u8]) -> Result<Self, Self::Error> {
        let addr = RedeemAddress::try_from(c)?;
        Ok(StakedStateAddress::BasicRedeem(addr))
    }
}

impl From<RedeemAddress> for StakedStateAddress {
    fn from(addr: RedeemAddress) -> Self {
        StakedStateAddress::BasicRedeem(addr)
    }
}

impl fmt::Display for StakedStateAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StakedStateAddress::BasicRedeem(a) => write!(f, "{}", a),
        }
    }
}

impl FromStr for StakedStateAddress {
    type Err = ErrorAddress;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(StakedStateAddress::BasicRedeem(RedeemAddress::from_str(s)?))
    }
}

/// represents the StakedState (account involved in staking)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct StakedState {
    pub nonce: Nonce,
    pub bonded: Coin,
    pub unbonded: Coin,
    pub unbonded_from: Timespec,
    pub address: StakedStateAddress,
    // TODO: slashing + jailing
}

/// the tree used in StakedState storage db has a hardcoded 32-byte keys,
/// this computes a key as blake2s(StakedState.address) where
/// the StakedState address itself is ETH-style address (20 bytes from keccak hash of public key)
pub fn to_stake_key(address: &StakedStateAddress) -> [u8; HASH_SIZE_256] {
    // TODO: prefix with zero
    match address {
        StakedStateAddress::BasicRedeem(a) => hash256::<Blake2s>(a),
    }
}

impl Default for StakedState {
    fn default() -> Self {
        StakedState::new(
            0,
            Coin::zero(),
            Coin::zero(),
            0,
            StakedStateAddress::BasicRedeem(RedeemAddress::default()),
        )
    }
}

impl StakedState {
    /// creates a new StakedState with given parameters
    pub fn new(
        nonce: Nonce,
        bonded: Coin,
        unbonded: Coin,
        unbonded_from: Timespec,
        address: StakedStateAddress,
    ) -> Self {
        StakedState {
            nonce,
            bonded,
            unbonded,
            unbonded_from,
            address,
        }
    }

    /// creates a StakedState at "genesis" (amount is either all bonded or unbonded depending on `bonded` argument)
    pub fn new_init(
        amount: Coin,
        genesis_time: Timespec,
        address: StakedStateAddress,
        bonded: bool,
    ) -> Self {
        if bonded {
            StakedState {
                nonce: 0,
                bonded: amount,
                unbonded: Coin::zero(),
                unbonded_from: genesis_time,
                address,
            }
        } else {
            StakedState {
                nonce: 0,
                bonded: Coin::zero(),
                unbonded: amount,
                unbonded_from: genesis_time,
                address,
            }
        }
    }

    /// in-place update after depositing a stake
    pub fn deposit(&mut self, amount: Coin) {
        self.nonce += 1;
        self.bonded = (self.bonded + amount).expect("should not be over the max supply");
    }

    /// in-place update after unbonding a bonded stake
    pub fn unbond(&mut self, amount: Coin, fee: Coin, unbonded_from: Timespec) {
        self.nonce += 1;
        self.unbonded_from = unbonded_from;
        self.bonded = (self.bonded - amount)
            .and_then(|x| x - fee)
            .expect("should not go below zero");
        self.unbonded = (self.unbonded + amount).expect("should not be over the max supply");
    }

    /// in-place update after withdrawing unbonded stake
    pub fn withdraw(&mut self) {
        self.nonce += 1;
        self.unbonded = Coin::zero();
    }

    /// the tree used in StakedState storage db has a hardcoded 32-byte keys,
    /// this computes a key as blake2s(StakedState.address) where
    /// the StakedState address itself is ETH-style address (20 bytes from keccak hash of public key)
    pub fn key(&self) -> [u8; HASH_SIZE_256] {
        to_stake_key(&self.address)
    }
}

/// attributes in StakedState-related transactions
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StakedStateOpAttributes {
    pub chain_hex_id: u8,
    // TODO: Other attributes?
}

impl StakedStateOpAttributes {
    pub fn new(chain_hex_id: u8) -> Self {
        StakedStateOpAttributes { chain_hex_id }
    }
}

impl Encode for StakedStateOpAttributes {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        dest.push_byte(0);
        dest.push_byte(1);
        dest.push_byte(self.chain_hex_id);
    }
}

impl Decode for StakedStateOpAttributes {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let tag = input.read_byte()?;
        let constructor_len = input.read_byte()?;
        match (tag, constructor_len) {
            (0, 1) => {
                let chain_hex_id: u8 = input.read_byte()?;
                Some(StakedStateOpAttributes { chain_hex_id })
            }
            _ => None,
        }
    }
}

/// takes UTXOs inputs, deposits them in the specified StakedState's bonded amount - fee
/// (updates StakedState's bonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DepositBondTx {
    pub inputs: Vec<TxoPointer>,
    pub to_staked_account: StakedStateAddress,
    pub attributes: StakedStateOpAttributes,
}

impl TransactionId for DepositBondTx {}

impl DepositBondTx {
    pub fn new(
        inputs: Vec<TxoPointer>,
        to_staked_account: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Self {
        DepositBondTx {
            inputs,
            to_staked_account,
            attributes,
        }
    }
}

impl fmt::Display for DepositBondTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for input in self.inputs.iter() {
            writeln!(f, "-> {}", input)?;
        }
        writeln!(f, "   {} (bonded) ->", self.to_staked_account)?;
        write!(f, "")
    }
}

/// updates the StakedState (TODO: implicit from the witness?) by moving some of the bonded amount - fee into unbonded,
/// and setting the unbonded_from to last_block_time+min_unbonding_time (network parameter)
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UnbondTx {
    pub value: Coin,
    pub nonce: Nonce,
    pub attributes: StakedStateOpAttributes,
}

impl TransactionId for UnbondTx {}

impl UnbondTx {
    pub fn new(value: Coin, nonce: Nonce, attributes: StakedStateOpAttributes) -> Self {
        UnbondTx {
            value,
            nonce,
            attributes,
        }
    }
}

impl fmt::Display for UnbondTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "unbonded: {} (nonce: {})", self.value, self.nonce)?;
        write!(f, "")
    }
}

/// takes the StakedState (TODO: implicit from the witness?) and creates UTXOs
/// (update's StakedState's unbonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WithdrawUnbondedTx {
    pub nonce: Nonce,
    pub outputs: Vec<TxOut>,
    pub attributes: TxAttributes,
}

impl TransactionId for WithdrawUnbondedTx {}

impl WithdrawUnbondedTx {
    pub fn new(nonce: Nonce, outputs: Vec<TxOut>, attributes: TxAttributes) -> Self {
        WithdrawUnbondedTx {
            nonce,
            outputs,
            attributes,
        }
    }
}

impl WithdrawUnbondedTx {
    /// returns the total transaction output amount (sum of all output amounts)
    pub fn get_output_total(&self) -> Result<Coin, CoinError> {
        sum_coins(self.outputs.iter().map(|x| x.value))
    }
}

impl fmt::Display for WithdrawUnbondedTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-> (unbonded) (nonce: {})", self.nonce)?;
        for output in self.outputs.iter() {
            writeln!(f, "   {} ->", output)?;
        }
        write!(f, "")
    }
}

/// A witness for StakedState operations
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum StakedStateOpWitness {
    BasicRedeem(EcdsaSignature),
}

impl StakedStateOpWitness {
    pub fn new(sig: EcdsaSignature) -> Self {
        StakedStateOpWitness::BasicRedeem(sig)
    }
}

impl Encode for StakedStateOpWitness {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        match *self {
            StakedStateOpWitness::BasicRedeem(ref sig) => {
                dest.push_byte(0);
                let (recovery_id, serialized_sig) = sig.serialize_compact();
                // recovery_id is one of 0 | 1 | 2 | 3
                let rid = recovery_id.to_i32() as u8;
                dest.push_byte(rid);
                serialized_sig.encode_to(dest);
            }
        }
    }
}

impl Decode for StakedStateOpWitness {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let tag = input.read_byte()?;
        match tag {
            0 => {
                let rid: u8 = input.read_byte()?;
                let raw_sig = RawSignature::decode(input)?;
                let recovery_id = RecoveryId::from_i32(i32::from(rid)).ok()?;
                let sig = RecoverableSignature::from_compact(&raw_sig, recovery_id).ok()?;
                Some(StakedStateOpWitness::BasicRedeem(sig))
            }
            _ => None,
        }
    }
}
