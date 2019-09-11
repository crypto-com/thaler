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
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
#[cfg(feature = "serde")]
use serde::de;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::prelude::v1::Vec;
#[cfg(feature = "hex")]
use std::str::FromStr;
// TODO: switch to normal signatures + explicit public key
#[cfg(feature = "hex")]
use crate::init::address::ErrorAddress;
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use std::convert::From;
#[cfg(feature = "hex")]
use std::convert::TryFrom;
#[cfg(feature = "hex")]
use std::fmt;

/// Each input is 34 bytes
///
/// Assuming maximum inputs allowed are 64,
/// So, maximum deposit transaction size (34 * 64) + 21 (address) + 1 (attributes) = 2198 bytes
const MAX_DEPOSIT_TX_SIZE: usize = 2200; // 2200 bytes

/// reference counter in the sparse patricia merkle tree/trie
pub type Count = u64;

/// StakedState update counter
pub type Nonce = u64;

/// StakedState address type
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum StakedStateAddress {
    BasicRedeem(RedeemAddress),
}

#[cfg(all(feature = "serde", feature = "hex"))]
impl Serialize for StakedStateAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(all(feature = "serde", feature = "hex"))]
impl<'de> Deserialize<'de> for StakedStateAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrVisitor;

        impl<'de> de::Visitor<'de> for StrVisitor {
            type Value = StakedStateAddress;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("staking address")
            }

            #[inline]
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                StakedStateAddress::from_str(value)
                    .map_err(|err| de::Error::custom(err.to_string()))
            }
        }

        deserializer.deserialize_str(StrVisitor)
    }
}

#[cfg(feature = "hex")]
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

#[cfg(feature = "hex")]
impl fmt::Display for StakedStateAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StakedStateAddress::BasicRedeem(a) => write!(f, "{}", a),
        }
    }
}

#[cfg(feature = "hex")]
impl FromStr for StakedStateAddress {
    type Err = ErrorAddress;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(StakedStateAddress::BasicRedeem(RedeemAddress::from_str(s)?))
    }
}

/// represents the StakedState (account involved in staking)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[cfg_attr(
    all(feature = "serde", feature = "hex"),
    derive(Deserialize, Serialize)
)]
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
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
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

/// takes UTXOs inputs, deposits them in the specified StakedState's bonded amount - fee
/// (updates StakedState's bonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Encode)]
#[cfg_attr(
    all(feature = "serde", feature = "hex"),
    derive(Serialize, Deserialize)
)]
pub struct DepositBondTx {
    pub inputs: Vec<TxoPointer>,
    pub to_staked_account: StakedStateAddress,
    pub attributes: StakedStateOpAttributes,
}

impl Decode for DepositBondTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let size = input
            .remaining_len()?
            .ok_or_else(|| "Unable to calculate size of input")?;

        if size > MAX_DEPOSIT_TX_SIZE {
            return Err("Input too large".into());
        }

        let inputs = <Vec<TxoPointer>>::decode(input)?;
        let to_staked_account = StakedStateAddress::decode(input)?;
        let attributes = StakedStateOpAttributes::decode(input)?;

        Ok(DepositBondTx {
            inputs,
            to_staked_account,
            attributes,
        })
    }
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

#[cfg(feature = "hex")]
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

#[cfg(feature = "hex")]
impl fmt::Display for UnbondTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "unbonded: {} (nonce: {})", self.value, self.nonce)?;
        write!(f, "")
    }
}

/// takes the StakedState (TODO: implicit from the witness?) and creates UTXOs
/// (update's StakedState's unbonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(
    all(feature = "serde", feature = "hex"),
    derive(Serialize, Deserialize)
)]
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

#[cfg(feature = "hex")]
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

    fn size_hint(&self) -> usize {
        match self {
            StakedStateOpWitness::BasicRedeem(_) => 66,
        }
    }
}

impl Decode for StakedStateOpWitness {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let tag = input.read_byte()?;
        match tag {
            0 => {
                let rid: u8 = input.read_byte()?;
                let raw_sig = RawSignature::decode(input)?;
                let recovery_id = RecoveryId::from_i32(i32::from(rid))
                    .map_err(|_| Error::from("Unable to parse recovery ID"))?;
                let sig = RecoverableSignature::from_compact(&raw_sig, recovery_id)
                    .map_err(|_| Error::from("Unable to create recoverable signature"))?;
                Ok(StakedStateOpWitness::BasicRedeem(sig))
            }
            _ => Err(Error::from("Invalid tag")),
        }
    }
}
