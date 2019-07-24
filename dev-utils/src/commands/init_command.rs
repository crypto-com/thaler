use std::str::FromStr;

use failure::{format_err, Error, ResultExt};
use hex::encode_upper;
use structopt::StructOpt;

use chain_abci::storage::account::{AccountStorage, AccountWrapper};
use chain_abci::storage::tx::StarlingFixedKey;
use chain_abci::storage::Storage;
use chain_core::common::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::init::config::{AccountType, InitNetworkParameters, InitialValidator};
use chain_core::init::{address::RedeemAddress, coin::Coin, config::InitConfig};
use chain_core::state::account::StakedState;
use chain_core::tx::fee::{LinearFee, Milli};
use chrono::offset::Utc;
use chrono::DateTime;
use kvdb_memorydb::create;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct InitialFeePolicy {
    base_fee: String,
    per_byte_fee: String,
}

#[derive(Debug, StructOpt)]
pub enum InitCommand {
    #[structopt(name = "init", about = "initialize")]
    Init {},
}

impl InitCommand {
    pub fn execute(&self) -> Result<(), Error> {
        Ok(())
    }

    fn init() -> Result<(), Error> {
        Ok(())
    }
}
