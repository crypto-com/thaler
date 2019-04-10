#![allow(missing_docs)]

use failure::ResultExt;
use hex::decode;
use serde::{Deserialize, Serialize};

use chain_core::init::config::InitConfig;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::Tx;
use client_common::{ErrorKind, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct Genesis {
    genesis: GenesisInner,
}

#[derive(Debug, Serialize, Deserialize)]
struct GenesisInner {
    genesis_time: String,
    chain_id: String,
    consensus_params: ConsensusParams,
    validators: Vec<ValidatorElement>,
    app_hash: String,
    app_state: InitConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConsensusParams {
    block: Block,
    evidence: Evidence,
    validator: ConsensusParamsValidator,
}

#[derive(Debug, Serialize, Deserialize)]
struct Block {
    max_bytes: String,
    max_gas: String,
    time_iota_ms: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Evidence {
    max_age: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConsensusParamsValidator {
    pub_key_types: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidatorElement {
    address: String,
    pub_key: PubKey,
    power: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PubKey {
    #[serde(rename = "type")]
    pub_key_type: String,
    value: String,
}

impl Genesis {
    /// Returns genesis transactions
    pub fn transactions(&self) -> Result<Vec<Tx>> {
        let (_, chain_id) = self
            .genesis
            .chain_id
            .split_at(self.genesis.chain_id.len() - 2);
        let chain_id = decode(chain_id).context(ErrorKind::DeserializationError)?[0];

        let app_state = &self.genesis.app_state;

        let transactions = app_state.generate_utxos(&TxAttributes::new(chain_id));

        Ok(transactions)
    }
}
