use crate::common::{hash256, Timespec, HASH_SIZE_256};
use crate::init::address::RedeemAddress;
use crate::init::coin::{sum_coins, Coin, CoinError};
#[cfg(not(feature = "mesalock_sgx"))]
use crate::init::config::SlashRatio;
use crate::tx::data::attribute::TxAttributes;
use crate::tx::data::input::TxoPointer;
use crate::tx::data::output::TxOut;
use crate::tx::witness::{tree::RawSignature, EcdsaSignature};
use crate::tx::TransactionId;
use blake2::Blake2s;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::de;
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::prelude::v1::Vec;
#[cfg(not(feature = "mesalock_sgx"))]
use std::str::FromStr;
// TODO: switch to normal signatures + explicit public key
#[cfg(not(feature = "mesalock_sgx"))]
use crate::init::address::ErrorAddress;
use crate::state::tendermint::{TendermintValidatorPubKey, TendermintVotePower};
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use std::convert::From;
#[cfg(not(feature = "mesalock_sgx"))]
use std::convert::TryFrom;
#[cfg(not(feature = "mesalock_sgx"))]
use std::fmt;
use std::prelude::v1::{String, ToString};

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

#[cfg(not(feature = "mesalock_sgx"))]
impl Serialize for StakedStateAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
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

#[cfg(not(feature = "mesalock_sgx"))]
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

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for StakedStateAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StakedStateAddress::BasicRedeem(a) => write!(f, "{}", a),
        }
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl FromStr for StakedStateAddress {
    type Err = ErrorAddress;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(StakedStateAddress::BasicRedeem(RedeemAddress::from_str(s)?))
    }
}

pub type ValidatorName = String;
pub type ValidatorSecurityContact = Option<String>;

/// holds state about a node responsible for transaction validation / block signing and service node whitelist management
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct CouncilNode {
    // validator name / moniker (just for reference / human use)
    pub name: ValidatorName,
    // optional security@... email address
    pub security_contact: ValidatorSecurityContact,
    // Tendermint consensus validator-associated public key
    pub consensus_pubkey: TendermintValidatorPubKey,
}

impl Encode for CouncilNode {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.name.encode_to(dest);
        match &self.security_contact {
            None => dest.push_byte(0),
            Some(c) => {
                dest.push_byte(1);
                c.encode_to(dest);
            }
        };
        self.consensus_pubkey.encode_to(dest);
    }
}

const MAX_STRING_LEN: usize = 255;

impl Decode for CouncilNode {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let name_raw: Vec<u8> = Vec::decode(input)?;
        if name_raw.len() > MAX_STRING_LEN {
            return Err(Error::from("Validator name longer than 255 chars"));
        }
        let name =
            String::from_utf8(name_raw).map_err(|_| Error::from("Invalid validator name"))?;
        let security_contact_raw: Option<Vec<u8>> = Option::decode(input)?;
        let security_contact = match security_contact_raw {
            Some(c) => {
                if c.len() > MAX_STRING_LEN {
                    return Err(Error::from("Security contact longer than 255 chars"));
                }
                Some(String::from_utf8(c).map_err(|_| Error::from("Invalid security contact"))?)
            }
            None => None,
        };
        let consensus_pubkey = TendermintValidatorPubKey::decode(input)?;
        Ok(CouncilNode::new_with_details(
            name,
            security_contact,
            consensus_pubkey,
        ))
    }
}

impl CouncilNode {
    pub fn new(consensus_pubkey: TendermintValidatorPubKey) -> Self {
        CouncilNode {
            name: "no-name".to_string(),
            security_contact: None,
            consensus_pubkey,
        }
    }

    pub fn new_with_details(
        name: ValidatorName,
        security_contact: ValidatorSecurityContact,
        consensus_pubkey: TendermintValidatorPubKey,
    ) -> Self {
        CouncilNode {
            name,
            security_contact,
            consensus_pubkey,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize))]
/// Metadata of a validator
pub struct CouncilNodeMetadata {
    /// Name of validator
    pub name: ValidatorName,
    /// Current voting power of validator
    pub voting_power: TendermintVotePower,
    /// Address of staking account of validator
    pub staking_address: StakedStateAddress,
    /// Optional security email address of validator
    pub security_contact: ValidatorSecurityContact,
    /// Tendermint consensus validator-associated public key
    pub tendermint_pubkey: TendermintValidatorPubKey,
}

/// Types of possible punishments
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub enum PunishmentKind {
    NonLive,
    ByzantineFault,
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for PunishmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PunishmentKind::NonLive => write!(f, "Non-live"),
            PunishmentKind::ByzantineFault => write!(f, "Byzantine fault"),
        }
    }
}

/// Details of a punishment for a staked state
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct Punishment {
    pub kind: PunishmentKind,
    pub jailed_until: Timespec,
    pub slash_amount: Option<Coin>,
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for CouncilNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -- {}", self.name, self.consensus_pubkey)
    }
}

/// represents the StakedState (account involved in staking)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct StakedState {
    pub nonce: Nonce,
    pub bonded: Coin,
    pub unbonded: Coin,
    pub unbonded_from: Timespec,
    pub address: StakedStateAddress,
    pub punishment: Option<Punishment>,
    pub council_node: Option<CouncilNode>,
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
            None,
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
        punishment: Option<Punishment>,
    ) -> Self {
        StakedState {
            nonce,
            bonded,
            unbonded,
            unbonded_from,
            address,
            punishment,
            council_node: None,
        }
    }

    /// creates a bonded StakedState with a validator metadata specified at genesis
    pub fn new_init_bonded(
        amount: Coin,
        genesis_time: Timespec,
        address: StakedStateAddress,
        council_node: Option<CouncilNode>,
    ) -> Self {
        StakedState {
            nonce: 0,
            bonded: amount,
            unbonded: Coin::zero(),
            unbonded_from: genesis_time,
            address,
            punishment: None,
            council_node,
        }
    }

    /// creates a StakedState at unbonded at specified time
    pub fn new_init_unbonded(amount: Coin, time: Timespec, address: StakedStateAddress) -> Self {
        StakedState {
            nonce: 0,
            bonded: Coin::zero(),
            unbonded: amount,
            unbonded_from: time,
            address,
            punishment: None,
            council_node: None,
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

    /// in-place update after node join request
    pub fn join_node(&mut self, council_node: CouncilNode) {
        self.nonce += 1;
        self.council_node = Some(council_node);
    }

    /// the tree used in StakedState storage db has a hardcoded 32-byte keys,
    /// this computes a key as blake2s(StakedState.address) where
    /// the StakedState address itself is ETH-style address (20 bytes from keccak hash of public key)
    pub fn key(&self) -> [u8; HASH_SIZE_256] {
        to_stake_key(&self.address)
    }

    /// Checks if current account is jailed
    #[inline]
    pub fn is_jailed(&self) -> bool {
        self.punishment.is_some()
    }

    /// Returns `jailed_until` for current account, `None` if current account is not jailed
    #[inline]
    pub fn jailed_until(&self) -> Option<Timespec> {
        self.punishment
            .as_ref()
            .map(|punishment| punishment.jailed_until)
    }

    /// Jails current account until given time
    pub fn jail_until(&mut self, jailed_until: Timespec, kind: PunishmentKind) {
        self.nonce += 1;
        self.punishment = Some(Punishment {
            kind,
            jailed_until,
            slash_amount: None,
        });
    }

    /// Unjails current account
    pub fn unjail(&mut self) {
        self.nonce += 1;
        self.punishment = None;
    }

    /// Slashes current account with given ratio and returns slashed amount
    /// TODO: previously this required base64, not sure why? check if this needs to be guarded, or it was a mistake
    #[cfg(not(feature = "mesalock_sgx"))]
    pub fn slash(
        &mut self,
        slash_ratio: SlashRatio,
        punishment_kind: PunishmentKind,
    ) -> Result<Coin, CoinError> {
        self.nonce += 1;

        let bonded_slash_value = self.bonded * slash_ratio;
        let unbonded_slash_value = self.unbonded * slash_ratio;

        self.bonded = (self.bonded - bonded_slash_value)?;
        self.unbonded = (self.unbonded - unbonded_slash_value)?;

        let slash_amount = (bonded_slash_value + unbonded_slash_value)?;

        if let Some(ref mut punishment) = self.punishment {
            punishment.slash_amount = Some(slash_amount);
            punishment.kind = punishment_kind;
        }

        Ok(slash_amount)
    }

    pub fn add_reward(&mut self, amount: Coin) -> Result<Coin, CoinError> {
        self.bonded = (self.bonded + amount)?;
        Ok(self.bonded)
    }
}

/// attributes in StakedState-related transactions
#[derive(Debug, Default, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct StakedStateOpAttributes {
    pub chain_hex_id: u8,
    // TODO: Other attributes?
}

impl StakedStateOpAttributes {
    pub fn new(chain_hex_id: u8) -> Self {
        StakedStateOpAttributes { chain_hex_id }
    }
}

/// bond status for StakedState initialize
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub enum StakedStateDestination {
    Bonded,
    UnbondedFromGenesis,
    UnbondedFromCustomTime(Timespec),
}

/// takes UTXOs inputs, deposits them in the specified StakedState's bonded amount - fee
/// (updates StakedState's bonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Encode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
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

#[cfg(not(feature = "mesalock_sgx"))]
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
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct UnbondTx {
    pub from_staked_account: StakedStateAddress,
    pub nonce: Nonce,
    pub value: Coin,
    pub attributes: StakedStateOpAttributes,
}

impl TransactionId for UnbondTx {}

impl UnbondTx {
    pub fn new(
        from_staked_account: StakedStateAddress,
        nonce: Nonce,
        value: Coin,
        attributes: StakedStateOpAttributes,
    ) -> Self {
        UnbondTx {
            from_staked_account,
            nonce,
            value,
            attributes,
        }
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for UnbondTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} unbonded: {} (nonce: {})",
            self.from_staked_account, self.value, self.nonce
        )?;
        write!(f, "")
    }
}

/// takes the StakedState (TODO: implicit from the witness?) and creates UTXOs
/// (update's StakedState's unbonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
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

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for WithdrawUnbondedTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-> (unbonded) (nonce: {})", self.nonce)?;
        for output in self.outputs.iter() {
            writeln!(f, "   {} ->", output)?;
        }
        write!(f, "")
    }
}

/// Unjails an account
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct UnjailTx {
    pub nonce: Nonce,
    pub address: StakedStateAddress,
    pub attributes: StakedStateOpAttributes,
}

impl TransactionId for UnjailTx {}

impl UnjailTx {
    #[inline]
    pub fn new(
        nonce: Nonce,
        address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Self {
        Self {
            nonce,
            address,
            attributes,
        }
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for UnjailTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "unjailed: {} (nonce: {})", self.address, self.nonce)?;
        write!(f, "")
    }
}

/// A witness for StakedState operations
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
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

#[cfg(test)]
mod test {

    use super::*;
    use quickcheck::quickcheck;
    use quickcheck::Arbitrary;
    use quickcheck::Gen;

    impl Arbitrary for CouncilNode {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let name = String::arbitrary(g);
            let mut raw_pubkey = [0u8; 32];
            g.fill_bytes(&mut raw_pubkey);
            let security_contact = if bool::arbitrary(g) {
                let contact = String::arbitrary(g);
                Some(contact)
            } else {
                None
            };
            CouncilNode::new_with_details(
                name,
                security_contact,
                TendermintValidatorPubKey::Ed25519(raw_pubkey),
            )
        }
    }

    fn has_valid_len(council_node: &CouncilNode) -> bool {
        match (council_node.name.len(), &council_node.security_contact) {
            (i, Some(ref c)) if (i <= MAX_STRING_LEN && c.len() <= MAX_STRING_LEN) => true,
            (i, None) if i <= MAX_STRING_LEN => true,
            _ => false,
        }
    }

    quickcheck! {
        // tests if decode(encode(x)) == x
        fn prop_encode_decode_council_node(council_node: CouncilNode) -> bool {
            if has_valid_len(&council_node) {
                let encoded = council_node.encode();
                CouncilNode::decode(&mut encoded.as_ref()).expect("decode council node") == council_node
            } else {
                let encoded = council_node.encode();
                CouncilNode::decode(&mut encoded.as_ref()).is_err()
            }
        }
    }
}
