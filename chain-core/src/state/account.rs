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
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::convert::From;
use std::fmt;
use std::prelude::v1::Vec;
use std::prelude::v1::{String, ToString};

/// reference counter in the sparse patricia merkle tree/trie
pub type Count = u64;

/// StakedState update counter:
/// the number of transactions that have the witness of the staking address.
pub type Nonce = u64;

/// human-readable moniker
pub type NodeName = String;
/// optional security@... email
pub type NodeSecurityContact = Option<String>;

/// FIXME: Encode, Decode implementations when MLS payloads are stabilized
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode)]
pub enum MLSInit {
    /// KeyPackage
    Genesis(Vec<u8>),
    /// payloads retrieved from other node's TDBE
    NodeJoin {
        /// MLSPlaintext -- Add
        add: Vec<u8>,
        /// MLSPlaintext -- Commit
        commit: Vec<u8>,
    },
}

/// the initial data a node submits to join a MLS group
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct ConfidentialInit {
    /// MLS credential with attestation payload
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub init_payload: MLSInit,
}

fn serialize_base64<S>(init_payload: &MLSInit, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match init_payload {
        MLSInit::Genesis(kp) => base64::encode(kp).serialize(serializer),
        _ => "FIXME".serialize(serializer),
    }
}

fn deserialize_base64<'de, D>(deserializer: D) -> Result<MLSInit, D::Error>
where
    D: Deserializer<'de>,
{
    let kp = base64::decode(String::deserialize(deserializer)?.as_bytes())
        .map_err(|e| D::Error::custom(format!("{}", e)))?;
    // FIXME: non-genesis
    Ok(MLSInit::Genesis(kp))
}

/// Information common to different node types
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct NodeCommonInfo {
    /// name / moniker (just for reference / human use)
    pub name: NodeName,
    /// optional security@... email address
    pub security_contact: NodeSecurityContact,
    /// serialized keypackage for MLS (https://tools.ietf.org/html/draft-ietf-mls-protocol-10)
    /// (expected that attestation payload will be a part of the cert extension, as done in TLS)
    pub confidential_init: ConfidentialInit,
}

impl fmt::Display for NodeCommonInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// TODO: size hint
impl Encode for NodeCommonInfo {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.name.encode_to(dest);
        match &self.security_contact {
            None => dest.push_byte(0),
            Some(c) => {
                dest.push_byte(1);
                c.encode_to(dest);
            }
        };
        // 0.5 test vectors specified it as Vec<u8> blob
        // FIXME: ok to break when stabilized in 0.6? will it break HW wallet parser?
        let temp: Vec<u8> = self.confidential_init.init_payload.encode();
        temp.encode_to(dest);
    }
}

fn decode_name_security_contact<I: Input>(
    input: &mut I,
) -> Result<(NodeName, NodeSecurityContact), Error> {
    let name_raw: Vec<u8> = Vec::decode(input)?;
    if name_raw.len() > MAX_STRING_LEN {
        return Err(Error::from("Validator name longer than 255 chars"));
    }
    let name = String::from_utf8(name_raw).map_err(|_| Error::from("Invalid validator name"))?;
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
    Ok((name, security_contact))
}

const MAX_STRING_LEN: usize = 255;

impl Decode for NodeCommonInfo {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let (name, security_contact) = decode_name_security_contact(input)?;
        // 0.5 test vectors specified it as Vec<u8> blob
        // FIXME: ok to break when stabilized in 0.6? will it break HW wallet parser?
        let temp: Vec<u8> = Vec::decode(input)?;
        let init_payload = MLSInit::decode(&mut temp.as_ref())?;
        Ok(NodeCommonInfo {
            name,
            security_contact,
            confidential_init: ConfidentialInit { init_payload },
        })
    }
}

/// holds state about a node responsible for transaction validation / block signing
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct CouncilNodeMeta {
    /// name, security contact and TDBE/MLS keypackage
    #[serde(flatten)]
    pub node_info: NodeCommonInfo,
    /// Tendermint consensus validator-associated public key
    pub consensus_pubkey: TendermintValidatorPubKey,
}

impl Encode for CouncilNodeMeta {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        // NOTE/WARN: the order of node_info + consensus pubkey
        // is swapped in order not to break 0.5 TX format
        // where it was like this
        self.node_info.name.encode_to(dest);
        match &self.node_info.security_contact {
            None => dest.push_byte(0),
            Some(c) => {
                dest.push_byte(1);
                c.encode_to(dest);
            }
        };
        self.consensus_pubkey.encode_to(dest);
        // 0.5 test vectors specified it as Vec<u8> blob
        // FIXME: ok to break when stabilized in 0.6? will it break HW wallet parser?
        let temp: Vec<u8> = self.node_info.confidential_init.init_payload.encode();
        temp.encode_to(dest);
    }
}

impl Decode for CouncilNodeMeta {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        // NOTE/WARN: the order of node_info + consensus pubkey
        // is swapped in order not to break 0.5 TX format
        // where it was like this
        let (name, security_contact) = decode_name_security_contact(input)?;
        let consensus_pubkey = TendermintValidatorPubKey::decode(input)?;
        // 0.5 test vectors specified it as Vec<u8> blob
        // FIXME: ok to break when stabilized in 0.6? will it break HW wallet parser?
        let temp: Vec<u8> = Vec::decode(input)?;
        let init_payload = MLSInit::decode(&mut temp.as_ref())?;
        Ok(CouncilNodeMeta::new_with_details(
            name,
            security_contact,
            consensus_pubkey,
            ConfidentialInit { init_payload },
        ))
    }
}

/// info about a node
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum NodeMetadata {
    /// validator
    CouncilNode(CouncilNodeMeta),
    /// full node
    CommunityNode(NodeCommonInfo),
}

impl fmt::Display for NodeMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeMetadata::CouncilNode(cm) => write!(f, "council node ({})", cm),
            NodeMetadata::CommunityNode(cm) => write!(f, "community node ({})", cm),
        }
    }
}

// TODO: size hint once MLS payloads are there
impl Encode for NodeMetadata {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        match self {
            NodeMetadata::CouncilNode(cm) => {
                dest.push_byte(0);
                cm.encode_to(dest);
            }
            NodeMetadata::CommunityNode(cm) => {
                dest.push_byte(1);
                cm.encode_to(dest);
            }
        }
    }
}

impl Decode for NodeMetadata {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let tag = input.read_byte()?;
        match tag {
            0 => {
                let node_info = CouncilNodeMeta::decode(input)?;
                Ok(NodeMetadata::CouncilNode(node_info))
            }
            1 => {
                let node_info = NodeCommonInfo::decode(input)?;
                Ok(NodeMetadata::CommunityNode(node_info))
            }
            _ => Err(Error::from("Unsupported Node variant")),
        }
    }
}

impl NodeMetadata {
    /// retrieves the add and commit proposals (if any)
    pub fn get_node_join_mls_init(&self) -> Option<(&[u8], &[u8])> {
        let init_payload = match self {
            NodeMetadata::CouncilNode(cm) => &cm.node_info.confidential_init.init_payload,
            NodeMetadata::CommunityNode(info) => &info.confidential_init.init_payload,
        };
        match init_payload {
            MLSInit::NodeJoin { add, commit } => Some((add, commit)),
            _ => None,
        }
    }

    /// create an empty council node (in testing etc.)
    pub fn new_council_node(
        consensus_pubkey: TendermintValidatorPubKey,
        confidential_init: ConfidentialInit,
    ) -> Self {
        NodeMetadata::CouncilNode(CouncilNodeMeta::new(consensus_pubkey, confidential_init))
    }

    /// new council node with full details
    pub fn new_council_node_with_details(
        name: NodeName,
        security_contact: NodeSecurityContact,
        consensus_pubkey: TendermintValidatorPubKey,
        confidential_init: ConfidentialInit,
    ) -> Self {
        NodeMetadata::CouncilNode(CouncilNodeMeta::new_with_details(
            name,
            security_contact,
            consensus_pubkey,
            confidential_init,
        ))
    }
}

impl CouncilNodeMeta {
    /// create an empty council node (in testing etc.)
    pub fn new(
        consensus_pubkey: TendermintValidatorPubKey,
        confidential_init: ConfidentialInit,
    ) -> Self {
        CouncilNodeMeta {
            node_info: NodeCommonInfo {
                name: "no-name".to_string(),
                security_contact: None,
                confidential_init,
            },
            consensus_pubkey,
        }
    }

    /// new council node with full details
    pub fn new_with_details(
        name: NodeName,
        security_contact: NodeSecurityContact,
        consensus_pubkey: TendermintValidatorPubKey,
        confidential_init: ConfidentialInit,
    ) -> Self {
        CouncilNodeMeta {
            node_info: NodeCommonInfo {
                name,
                security_contact,
                confidential_init,
            },
            consensus_pubkey,
        }
    }
}

/// Types of possible punishments
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize,
)]
pub enum PunishmentKind {
    /// liveness fault
    NonLive,
    /// byzantine fault (double vote signing initially)
    ByzantineFault,
}

impl fmt::Display for PunishmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PunishmentKind::NonLive => write!(f, "Non-live"),
            PunishmentKind::ByzantineFault => write!(f, "Byzantine fault"),
        }
    }
}

/// Details of a punishment for a staked state
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize)]
pub struct SlashRecord {
    /// why
    pub kind: PunishmentKind,
    /// when
    pub time: Timespec,
    /// how much
    pub amount: Coin,
}

impl fmt::Display for CouncilNodeMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -- {}", self.node_info, self.consensus_pubkey)
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize)]
pub struct Validator {
    /// council node metadata
    pub council_node: CouncilNodeMeta,
    /// if jailed, it's specified until what block time
    pub jailed_until: Option<Timespec>,

    /// when it became inactive (from block time)
    pub inactive_time: Option<Timespec>,
    /// which block it became inactive
    pub inactive_block: Option<BlockHeight>,

    /// last N (10?) used consensus pubkeys/addresses
    #[serde(skip)]
    pub used_validator_addresses: Vec<(TendermintValidatorAddress, Timespec)>,
}

impl Validator {
    /// creates an empty validator with only council node metadata (for tests?)
    pub fn new(council_node: CouncilNodeMeta) -> Self {
        Self {
            council_node,
            jailed_until: None,
            inactive_time: None,
            inactive_block: None,
            used_validator_addresses: Vec::new(),
        }
    }

    /// extracts validator address from the pubkey
    pub fn validator_address(&self) -> TendermintValidatorAddress {
        TendermintValidatorAddress::from(&self.council_node.consensus_pubkey)
    }

    /// checks if jailed
    pub fn is_jailed(&self) -> bool {
        self.jailed_until.is_some()
    }

    /// checks if active
    pub fn is_active(&self) -> bool {
        self.inactive_time.is_none()
    }

    /// extra dynamic assertions for fuzzer etc.
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

    /// updates this state to be "jailed"
    pub fn jail(
        &mut self,
        block_time: Timespec,
        block_height: BlockHeight,
        jail_duration: Timespec,
    ) -> Timespec {
        assert!(!self.is_jailed());
        let jailed_until = block_time.saturating_add(jail_duration);

        self.jailed_until = Some(jailed_until);
        if self.is_active() {
            self.inactivate(block_time, block_height);
        }

        jailed_until
    }

    /// updates this state to be "inactive"
    pub fn inactivate(&mut self, block_time: Timespec, block_height: BlockHeight) {
        assert!(self.is_active());
        self.inactive_time = Some(block_time);
        self.inactive_block = Some(block_height);
    }

    /// updates this state to be unjailed
    pub fn unjail(&mut self) {
        assert!(self.is_jailed());
        self.jailed_until = None;
    }
}

/// represents node state metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize)]
pub enum NodeState {
    /// information related to council nodes (validator metadata + keypackage from TDBE)
    CouncilNode(Validator),
    /// information related to community nodes (keypackage from TDBE)
    CommunityNode(NodeCommonInfo),
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize)]
pub struct StakedState {
    /// "from" operations counter
    pub nonce: Nonce,
    /// bonded amount used to determine voting power
    pub bonded: Coin,
    /// amount unbonded for future withdrawal
    pub unbonded: Coin,
    /// time when unbonded amount can be withdrawn
    pub unbonded_from: Timespec,
    /// the address used (to check transaction withness against)
    pub address: StakedStateAddress,
    /// node metadata
    pub node_meta: Option<NodeState>,
    /// record the last slash only for query
    pub last_slash: Option<SlashRecord>,
}

/// the tree used in StakedState storage db has a hardcoded 32-byte keys,
/// this computes a key as blake3(0 || StakedState.address) where
/// the StakedState address itself is ETH-style address (20 bytes from keccak hash of public key)
pub fn to_stake_key(address: &StakedStateAddress) -> [u8; HASH_SIZE_256] {
    match address {
        StakedStateAddress::BasicRedeem(a) => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&[0u8]);
            hasher.update(a);
            hasher.finalize()
        }
    }
    .into()
}

impl StakedState {
    /// checks if it contains council node metadata
    pub fn has_council_node_meta(&self) -> bool {
        matches!(&self.node_meta, Some(NodeState::CouncilNode(_x)))
    }

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
            node_meta: validator.map(NodeState::CouncilNode),
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
            node_meta: None,
            last_slash: None,
        }
    }

    /// Create with informations in genesis config.
    pub fn from_genesis(
        address: StakedStateAddress,
        genesis_time: Timespec,
        destination: &StakedStateDestination,
        amount: Coin,
        council_node: Option<CouncilNodeMeta>,
    ) -> Self {
        let mut staking = Self::default(address);
        match destination {
            StakedStateDestination::Bonded => {
                staking.node_meta = council_node.map(|x| NodeState::CouncilNode(Validator::new(x)));
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
        if let Some(NodeState::CouncilNode(v)) = &self.node_meta {
            v.is_jailed()
        } else {
            false
        }
    }

    /// extra dynamic assertions
    #[cfg(debug_assertions)]
    pub fn check_invariants(&self, minimal_required_staking: Coin) {
        // check: Invariant 4.1
        (self.bonded + self.unbonded).unwrap();

        // check: Invariant 4.2
        if let Some(NodeState::CouncilNode(val)) = &self.node_meta {
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
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum StakedStateDestination {
    /// initialize in genesis as bonded
    Bonded,
    /// initialize in genesis as unbonded with time to withdraw from genesis immediately
    UnbondedFromGenesis,
    /// initialize in genesis as unbonded with some custom time it can be withdrawn at
    UnbondedFromCustomTime(Timespec),
}

#[cfg(test)]
mod test {

    use super::*;
    use quickcheck::quickcheck;
    use quickcheck::Arbitrary;
    use quickcheck::Gen;

    impl Arbitrary for CouncilNodeMeta {
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
            // TODO: generate well-formed keypackage
            let keypackage: Vec<u8> = Vec::arbitrary(g);
            CouncilNodeMeta::new_with_details(
                name,
                security_contact,
                TendermintValidatorPubKey::Ed25519(raw_pubkey),
                ConfidentialInit {
                    init_payload: MLSInit::Genesis(keypackage),
                },
            )
        }
    }

    fn has_valid_len(council_node: &CouncilNodeMeta) -> bool {
        match (
            council_node.node_info.name.len(),
            &council_node.node_info.security_contact,
        ) {
            (i, Some(ref c)) if (i <= MAX_STRING_LEN && c.len() <= MAX_STRING_LEN) => true,
            (i, None) if i <= MAX_STRING_LEN => true,
            _ => false,
        }
    }

    quickcheck! {
        // tests if decode(encode(x)) == x
        fn prop_encode_decode_council_node(council_node: CouncilNodeMeta) -> bool {
            if has_valid_len(&council_node) {
                let encoded = council_node.encode();
                CouncilNodeMeta::decode(&mut encoded.as_ref()).expect("decode council node") == council_node
            } else {
                let encoded = council_node.encode();
                CouncilNodeMeta::decode(&mut encoded.as_ref()).is_err()
            }
        }
    }
}
