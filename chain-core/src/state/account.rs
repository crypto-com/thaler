use crate::common::{hash256, Timespec, HASH_SIZE_256};
use crate::init::address::RedeemAddress;
use crate::init::coin::{sum_coins, Coin, CoinError};
use crate::tx::data::attribute::TxAttributes;
use crate::tx::data::input::TxoPointer;
use crate::tx::data::output::TxOut;
use crate::tx::witness::{tree::RawSignature, EcdsaSignature};
use crate::tx::TransactionId;
use blake2::Blake2s;
use core::cmp::Ordering;
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
use crate::state::tendermint::{
    BlockHeight, TendermintValidatorAddress, TendermintValidatorPubKey, TendermintVotePower,
};
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
pub struct SlashRecord {
    // why
    pub kind: PunishmentKind,
    // when
    pub time: Timespec,
    // how much
    pub amount: Coin,
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for CouncilNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -- {}", self.name, self.consensus_pubkey)
    }
}

/// Validator meta
///
/// Invariant 1.1:
///   ```plain
///   (inactive_time.is_none() && inactive_block.is_none()) ||
///   (inactive_time.is_some() && inactive_block.is_some())
///   ```
///
/// Invariant 1.2:
///   `! (is_jailed() && is_active())`
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct Validator {
    pub council_node: CouncilNode,
    pub jailed_until: Option<Timespec>,

    pub inactive_time: Option<Timespec>,
    pub inactive_block: Option<BlockHeight>,

    #[cfg_attr(not(feature = "mesalock_sgx"), serde(skip))]
    pub used_validator_addresses: Vec<(TendermintValidatorAddress, Timespec)>,
}

impl Validator {
    pub fn new(council_node: CouncilNode) -> Self {
        Self {
            council_node,
            jailed_until: None,
            inactive_time: None,
            inactive_block: None,
            used_validator_addresses: Vec::new(),
        }
    }

    pub fn validator_address(&self) -> TendermintValidatorAddress {
        TendermintValidatorAddress::from(&self.council_node.consensus_pubkey)
    }

    pub fn is_jailed(&self) -> bool {
        self.jailed_until.is_some()
    }

    pub fn is_active(&self) -> bool {
        self.inactive_time.is_none()
    }

    #[cfg(debug_assertions)]
    pub fn check_invariants(&self) {
        // check: Invariant 1.1
        assert!(
            (self.inactive_time.is_none() && self.inactive_block.is_none())
                || (self.inactive_time.is_some() && self.inactive_block.is_some())
        );

        // check: Invariant 1.2
        assert_eq!(self.is_jailed() && self.is_active(), false);
    }

    pub fn jail(
        &mut self,
        block_time: Timespec,
        block_height: BlockHeight,
        jail_duration: Timespec,
    ) {
        assert!(!self.is_jailed());
        self.jailed_until = Some(block_time.saturating_add(jail_duration));
        if self.is_active() {
            self.inactivate(block_time, block_height);
        }
    }

    pub fn inactivate(&mut self, block_time: Timespec, block_height: BlockHeight) {
        assert!(self.is_active());
        self.inactive_time = Some(block_time);
        self.inactive_block = Some(block_height);
    }

    pub fn unjail(&mut self) {
        assert!(self.is_jailed());
        self.jailed_until = None;
    }
}

/// represents the StakedState (account involved in staking)
/// Invariant 4.1:
///   - bonded + unbonded <= max supply
///
/// Invariant 4.2:
///   ```plain
///   if let Some(val) = validator {
///       if val.is_active() {
///           (bonded >= minimal_required_staking && !val.is_jailed())
///       }
///   }
///   ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct StakedState {
    pub nonce: Nonce,
    pub bonded: Coin,
    pub unbonded: Coin,
    pub unbonded_from: Timespec,
    pub address: StakedStateAddress,
    pub validator: Option<Validator>,
    // record the last slash only for query
    pub last_slash: Option<SlashRecord>,
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

impl StakedState {
    /// creates a new StakedState with given parameters
    pub fn new(
        nonce: Nonce,
        bonded: Coin,
        unbonded: Coin,
        unbonded_from: Timespec,
        address: StakedStateAddress,
        validator: Option<Validator>,
    ) -> Self {
        Self {
            nonce,
            bonded,
            unbonded,
            unbonded_from,
            address,
            validator,
            last_slash: None,
        }
    }

    /// Create a default StakedState with address.
    pub fn default(address: StakedStateAddress) -> Self {
        Self {
            address,
            nonce: 0,
            bonded: Coin::zero(),
            unbonded: Coin::zero(),
            unbonded_from: 0,
            validator: None,
            last_slash: None,
        }
    }

    /// Create with informations in genesis config.
    pub fn from_genesis(
        address: StakedStateAddress,
        genesis_time: Timespec,
        destination: &StakedStateDestination,
        amount: Coin,
        council_node: Option<CouncilNode>,
    ) -> Self {
        let mut staking = Self::default(address);
        match destination {
            StakedStateDestination::Bonded => {
                staking.validator = council_node.map(Validator::new);
                staking.bonded = amount;
                staking.unbonded_from = genesis_time;
            }
            StakedStateDestination::UnbondedFromGenesis => {
                staking.unbonded = amount;
                staking.unbonded_from = genesis_time;
            }
            StakedStateDestination::UnbondedFromCustomTime(time) => {
                staking.unbonded = amount;
                staking.unbonded_from = *time;
            }
        };
        staking
    }

    /// Key of merkle storage
    pub fn key(&self) -> [u8; HASH_SIZE_256] {
        to_stake_key(&self.address)
    }

    /// Return is jailed, non validator default to false.
    pub fn is_jailed(&self) -> bool {
        if let Some(v) = &self.validator {
            v.is_jailed()
        } else {
            false
        }
    }

    pub fn sort_key(&self) -> ValidatorSortKey {
        ValidatorSortKey::new(self.bonded, self.address)
    }

    #[cfg(debug_assertions)]
    pub fn check_invariants(&self, minimal_required_staking: Coin) {
        // check: Invariant 4.1
        (self.bonded + self.unbonded).unwrap();

        // check: Invariant 4.2
        if let Some(val) = &self.validator {
            if val.is_active() {
                assert!(self.bonded >= minimal_required_staking && !val.is_jailed());
            }
        }
    }

    /// Increment nonce by 1
    pub fn inc_nonce(&mut self) {
        self.nonce = self.nonce.wrapping_add(1);
    }
}

/// order by bonded desc, staking_address
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct ValidatorSortKey {
    pub bonded: Coin,
    pub address: StakedStateAddress,
}
impl Ord for ValidatorSortKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.bonded.cmp(&other.bonded) {
            Ordering::Equal => self.address.cmp(&other.address),
            ordering => ordering.reverse(),
        }
    }
}
impl PartialOrd for ValidatorSortKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl ValidatorSortKey {
    pub fn new(bonded: Coin, address: StakedStateAddress) -> Self {
        Self { bonded, address }
    }
}

/// attributes in StakedState-related transactions
#[derive(Debug, Default, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct StakedStateOpAttributes {
    pub chain_hex_id: u8,
    pub app_version: u64,
}

impl StakedStateOpAttributes {
    pub fn new(chain_hex_id: u8) -> Self {
        StakedStateOpAttributes {
            chain_hex_id,
            app_version: crate::APP_VERSION,
        }
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
