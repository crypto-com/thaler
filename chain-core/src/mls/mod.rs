use crate::tx::TransactionId;
use parity_scale_codec::{Decode, Encode};
use std::prelude::v1::Vec;

/// A wrapper type for payloads generated and exchanged
/// by a part of "Transaction Data Bootstrapping Enclave" (TDBE)
/// ref: https://github.com/crypto-com/chain-docs/blob/master/docs/modules/tdbe.md
/// TODO: currently, Vec<u8> payloads are assumed to be TLS encoded,
/// but this may switch to SCALE
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub enum MLSHandshakeAux {
    /// the reaction to node joining or leaving (nodejoin tx or events)
    CommitProposal {
        /// MLSPlaintext -- any proposals (Add or Remove), the last one is assumed to be Commit
        messages: Vec<Vec<u8>>,
        /// Welcome -- if there are any Add proposals, there should be a welcome with encrypted paths/epochs for new joiners
        welcome: Option<Vec<u8>>,
    },
    /// when the keypackage is about to expire, the member submits its renewal
    SelfUpdateProposal {
        /// MLSPlaintext -- Update
        proposal: Vec<u8>,
        /// MLSPlaintext -- Commit
        commit: Vec<u8>,
    },
    /// DLEQ proof: https://github.com/crypto-com/chain/pull/1805/files#diff-f5bad205e7530b482b54bda5e678249aR23
    /// + some way to refer to the message part that went wrong
    /// FIXME: spec/data type
    MsgNack(Vec<u8>),
}

impl TransactionId for MLSHandshakeAux {}
