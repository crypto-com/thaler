use crate::state::account::{CouncilNode, Nonce, StakedStateAddress, StakedStateOpAttributes};
use crate::tx::TransactionId;
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "hex")]
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
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NodeJoinRequestTx {
    pub nonce: Nonce,
    pub address: StakedStateAddress,
    pub attributes: StakedStateOpAttributes,
    pub node_meta: CouncilNode,
}

impl TransactionId for NodeJoinRequestTx {}

impl NodeJoinRequestTx {
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

#[cfg(feature = "hex")]
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
