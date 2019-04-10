#![allow(missing_docs)]

use base64::decode;
use failure::ResultExt;
use serde::{Deserialize, Serialize};

use chain_core::tx::TxAux;
use client_common::{ErrorKind, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct Block {
    block_meta: BlockMeta,
    block: BlockInner,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockInner {
    header: Header,
    data: Data,
    last_commit: LastCommit,
}

#[derive(Debug, Serialize, Deserialize)]
struct Data {
    txs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    version: Version,
    chain_id: String,
    height: String,
    time: String,
    num_txs: String,
    total_txs: String,
    last_block_id: BlockId,
    last_commit_hash: String,
    data_hash: String,
    validators_hash: String,
    next_validators_hash: String,
    consensus_hash: String,
    app_hash: String,
    last_results_hash: String,
    evidence_hash: String,
    proposer_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockId {
    hash: String,
    parts: Parts,
}

#[derive(Debug, Serialize, Deserialize)]
struct Parts {
    total: String,
    hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Version {
    block: String,
    app: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LastCommit {
    block_id: BlockId,
    precommits: Vec<Precommit>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Precommit {
    #[serde(rename = "type")]
    precommit_type: i64,
    height: String,
    round: String,
    block_id: BlockId,
    timestamp: String,
    validator_address: String,
    validator_index: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockMeta {
    block_id: BlockId,
    header: Header,
}

impl Block {
    /// Returns transactions in a block (this may also contain invalid transactions)
    pub fn transactions(&self) -> Result<Vec<TxAux>> {
        self.block
            .data
            .txs
            .iter()
            .map(|raw_tx| Ok(decode(&raw_tx).context(ErrorKind::DeserializationError)?))
            .map(|bytes: Result<Vec<u8>>| {
                Ok(rlp::decode(&bytes?).context(ErrorKind::DeserializationError)?)
            })
            .collect::<Result<Vec<TxAux>>>()
    }
}
