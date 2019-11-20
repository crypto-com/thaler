//! Lite tendermint client
use serde::{Deserialize, Serialize};
use tendermint::{block::Header, validator};

use crate::tendermint::client::Client;
use crate::Result;

///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustedState {
    /// last header
    pub header: Option<Header>,
    /// current validator set
    pub validators: validator::Set,
}

/// get genesis validator set
pub fn get_genesis_validators<C>(client: &C) -> Result<validator::Set>
where
    C: Client,
{
    Ok(validator::Set::new(client.genesis()?.validators))
}
