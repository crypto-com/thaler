use crate::keypackage::{self, Timespec};
use crate::message::MLSPlaintext;
use crate::Codec;
use ra_client::{CertVerifyResult, ENCLAVE_CERT_VERIFIER};

/// FIXME: needs design/spec https://github.com/crypto-com/chain-docs/issues/141
/// of possible errors
#[derive(thiserror::Error, Debug)]
pub enum NodeJoinError {
    #[error("decoding failed")]
    DecodeError,
    #[error("verification error: {0}")]
    VerifyError(#[from] keypackage::Error),
}

/// FIXME: needs design/spec https://github.com/crypto-com/chain-docs/issues/141
/// of what needs to be returned
pub struct NodeJoinResult {
    pub info: CertVerifyResult,
}

/// FIXME: needs design/spec https://github.com/crypto-com/chain-docs/issues/141
/// this may need to be passed in more arguments, e.g. groupcontext or whatever the chain-abci
/// can maintain
pub fn check_nodejoin(
    add_proposal: &[u8],
    _commit: &[u8],
    block_time: Timespec,
) -> Result<NodeJoinResult, NodeJoinError> {
    // FIXME: many missing validations
    let proposal = MLSPlaintext::read_bytes(add_proposal).ok_or(NodeJoinError::DecodeError)?;
    let add = proposal.get_add().ok_or(NodeJoinError::DecodeError)?;

    let info = add
        .key_package
        .verify(&*ENCLAVE_CERT_VERIFIER, block_time)
        .map_err(NodeJoinError::VerifyError)?;
    Ok(NodeJoinResult { info })
}
