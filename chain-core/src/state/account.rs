mod address;
mod op;
use crate::common::{Timespec, HASH_SIZE_256};
use crate::init::coin::Coin;
use crate::state::tendermint::{
    BlockHeight, TendermintValidatorAddress, TendermintValidatorPubKey,
};
pub use crate::state::validator::UnjailTx;
pub use address::StakedStateAddress;
pub use op::data::attribute::StakedStateOpAttributes;
pub use op::data::deposit::DepositBondTx;
pub use op::data::unbond::UnbondTx;
pub use op::data::withdraw::WithdrawUnbondedTx;
pub use op::witness::StakedStateOpWitness;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::convert::From;
#[cfg(not(feature = "mesalock_sgx"))]
use std::fmt;
use std::prelude::v1::Vec;
use std::prelude::v1::{String, ToString};

/// reference counter in the sparse patricia merkle tree/trie
pub type Count = u64;

/// StakedState update counter
pub type Nonce = u64;

pub type ValidatorName = String;
pub type ValidatorSecurityContact = Option<String>;

/// the initial data a node submits to join a MLS group
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct ConfidentialInit {
    /// MLS credential with attestation payload
    #[cfg_attr(
        not(feature = "mesalock_sgx"),
        serde(
            serialize_with = "serialize_base64",
            deserialize_with = "deserialize_base64"
        )
    )]
    pub cert: Vec<u8>,
}

#[cfg(not(feature = "mesalock_sgx"))]
fn serialize_base64<S>(cert: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    base64::encode(cert).serialize(serializer)
}

#[cfg(not(feature = "mesalock_sgx"))]
fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    base64::decode(String::deserialize(deserializer)?.as_bytes())
        .map_err(|e| D::Error::custom(format!("{}", e)))
}

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
    // X.509 credential payload for MLS (https://tools.ietf.org/html/draft-ietf-mls-protocol-09)
    // (expected that attestation payload will be a part of the cert extension, as done in TLS)
    pub confidential_init: ConfidentialInit,
}

// TODO: size hint once MLS payloads are there
impl Encode for CouncilNode {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        // in the case there's a need for other node types or wildly different metadata
        dest.push_byte(0);
        self.name.encode_to(dest);
        match &self.security_contact {
            None => dest.push_byte(0),
            Some(c) => {
                dest.push_byte(1);
                c.encode_to(dest);
            }
        };
        self.consensus_pubkey.encode_to(dest);
        self.confidential_init.cert.encode_to(dest);
    }
}

const MAX_STRING_LEN: usize = 255;

impl Decode for CouncilNode {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let tag = input.read_byte()?;
        if tag != 0 {
            return Err(Error::from("Unsupported Council Node variant"));
        }
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
        let confidential_init: Vec<u8> = Vec::decode(input)?;
        Ok(CouncilNode::new_with_details(
            name,
            security_contact,
            consensus_pubkey,
            ConfidentialInit {
                cert: confidential_init,
            },
        ))
    }
}

impl CouncilNode {
    pub fn new(
        consensus_pubkey: TendermintValidatorPubKey,
        confidential_init: ConfidentialInit,
    ) -> Self {
        CouncilNode {
            name: "no-name".to_string(),
            security_contact: None,
            consensus_pubkey,
            confidential_init,
        }
    }

    pub fn new_with_details(
        name: ValidatorName,
        security_contact: ValidatorSecurityContact,
        consensus_pubkey: TendermintValidatorPubKey,
        confidential_init: ConfidentialInit,
    ) -> Self {
        CouncilNode {
            name,
            security_contact,
            consensus_pubkey,
            confidential_init,
        }
    }
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
/// this computes a key as blake3(StakedState.address) where
/// the StakedState address itself is ETH-style address (20 bytes from keccak hash of public key)
pub fn to_stake_key(address: &StakedStateAddress) -> [u8; HASH_SIZE_256] {
    // TODO: prefix with zero
    match address {
        StakedStateAddress::BasicRedeem(a) => blake3::hash(a),
    }
    .into()
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

/// bond status for StakedState initialize
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub enum StakedStateDestination {
    Bonded,
    UnbondedFromGenesis,
    UnbondedFromCustomTime(Timespec),
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
            // TODO: generate well-formed credentials
            let cert: Vec<u8> = Vec::arbitrary(g);
            CouncilNode::new_with_details(
                name,
                security_contact,
                TendermintValidatorPubKey::Ed25519(raw_pubkey),
                ConfidentialInit { cert },
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
