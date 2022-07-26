use crate::tx::data::TxId;
#[cfg(feature = "new-txid")]
use crate::tx::TaggedTransaction;
use crate::tx::TransactionId;
use parity_scale_codec::{Decode, Encode};
use std::prelude::v1::Vec;

/// message to remove members
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct CommitRemoveTx {
    proposals: Vec<Vec<u8>>, // [MLSPlaintext] -- Remove
    commit: Vec<u8>,         // MLSPlaintext -- Commit
}

#[cfg(not(feature = "new-txid"))]
impl TransactionId for CommitRemoveTx {}

#[cfg(feature = "new-txid")]
impl From<CommitRemoveTx> for TaggedTransaction {
    fn from(tx: CommitRemoveTx) -> TaggedTransaction {
        TaggedTransaction::MLSRemoveCommitProposal(tx)
    }
}

/// message to update its own leaf
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct SelfUpdateProposalTx {
    proposal: Vec<u8>, // MLSPlaintext -- Update
    commit: Vec<u8>,   // MLSPlaintext -- Commit
}

#[cfg(not(feature = "new-txid"))]
impl TransactionId for SelfUpdateProposalTx {}

#[cfg(feature = "new-txid")]
impl From<SelfUpdateProposalTx> for TaggedTransaction {
    fn from(tx: SelfUpdateProposalTx) -> TaggedTransaction {
        TaggedTransaction::MLSSelfUpdateProposal(tx)
    }
}

/// FIXME: NackMsg in mls/extras
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct NackMsgTx(Vec<u8>);

#[cfg(not(feature = "new-txid"))]
impl TransactionId for NackMsgTx {}

#[cfg(feature = "new-txid")]
impl From<NackMsgTx> for TaggedTransaction {
    fn from(tx: NackMsgTx) -> TaggedTransaction {
        TaggedTransaction::MLSMsgNack(tx)
    }
}

/// A wrapper type for payloads generated and exchanged
/// by a part of "Transaction Data Bootstrapping Enclave" (TDBE)
/// ref: https://github.com/crypto-com/thaler-docs/blob/master/docs/modules/tdbe.md
/// TODO: currently, Vec<u8> payloads are assumed to be TLS encoded,
/// but this may switch to SCALE
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub enum MLSHandshakeAux {
    /// the reaction to node leaving (keypackage expire, unbond tx or events)
    RemoveCommitProposal(CommitRemoveTx),
    /// when the keypackage is about to expire, the member submits its renewal
    SelfUpdateProposal(SelfUpdateProposalTx),
    /// DLEQ proof: https://github.com/crypto-com/chain/pull/1805/files#diff-f5bad205e7530b482b54bda5e678249aR23
    /// + some way to refer to the message part that went wrong
    /// FIXME: spec/data type
    MsgNack(NackMsgTx),
}

impl MLSHandshakeAux {
    /// retrieves a TX ID (currently blake3(<tx type tag> || scale_codec_bytes(tx)))
    pub fn tx_id(&self) -> TxId {
        match self {
            MLSHandshakeAux::RemoveCommitProposal(tx) => tx.id(),
            MLSHandshakeAux::SelfUpdateProposal(tx) => tx.id(),
            MLSHandshakeAux::MsgNack(tx) => tx.id(),
        }
    }
}
