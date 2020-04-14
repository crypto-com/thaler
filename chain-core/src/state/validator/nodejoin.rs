use crate::state::account::{CouncilNode, Nonce, StakedStateAddress, StakedStateOpAttributes};
use crate::tx::TransactionId;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Serialize};
#[cfg(not(feature = "mesalock_sgx"))]
use std::fmt;

/// Submits a proposal to add a council node:
/// if there are less than max cap validators or the associated stake
/// is more than the smallest one in the validator set,
/// the validator set will be updated.
///
/// tx-validation should check that:
/// - the address and the consensus_pubkey are not in the
/// - the associated staked state is ok (not jailed etc.)
/// - the bonded amount in the stake state is more than the minimal required one
/// - the witness is correct
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct NodeJoinRequestTx {
    /// the expected nonce on the corresponding state
    pub nonce: Nonce,
    /// the expected address on the corresponding state
    pub address: StakedStateAddress,
    /// the versioning and network identifier
    pub attributes: StakedStateOpAttributes,
    /// council node information, both consensus critical (validator pubkey...)
    /// as well as informational (security contact...)
    pub node_meta: CouncilNode,
}

impl Decode for NodeJoinRequestTx {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let nonce = Nonce::decode(input)?;
        let address = StakedStateAddress::decode(input)?;
        let attributes = StakedStateOpAttributes::decode(input)?;
        let node_meta = CouncilNode::decode(input)?;

        Ok(NodeJoinRequestTx {
            nonce,
            address,
            attributes,
            node_meta,
        })
    }
}

// TODO: size hint as node_meta needs more info
impl Encode for NodeJoinRequestTx {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        dest.push(&self.nonce);
        dest.push(&self.address);
        dest.push(&self.attributes);
        dest.push(&self.node_meta);
    }
}

impl TransactionId for NodeJoinRequestTx {}

impl NodeJoinRequestTx {
    /// constructs a new node join request transaction from the provided components
    #[inline]
    pub fn new(
        nonce: Nonce,
        address: StakedStateAddress,
        attributes: StakedStateOpAttributes,
        node_meta: CouncilNode,
    ) -> Self {
        Self {
            nonce,
            address,
            attributes,
            node_meta,
        }
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
impl fmt::Display for NodeJoinRequestTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "address: {} (nonce: {}) to add {}",
            self.address, self.nonce, self.node_meta
        )?;
        write!(f, "")
    }
}
