//! Lite tendermint client
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::{Deserialize, Serialize};
use tendermint::{block::Header, validator};

use crate::tendermint::client::Client;
use crate::Result as CommonResult;

///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustedState {
    /// last header
    pub header: Option<Header>,
    /// current validator set
    pub validators: validator::Set,
}

impl TrustedState {
    /// construct genesis trusted state
    pub fn genesis(genesis_validators: Vec<validator::Info>) -> TrustedState {
        TrustedState {
            header: None,
            validators: validator::Set::new(genesis_validators),
        }
    }
}

impl Encode for TrustedState {
    fn encode_to<T: Output>(&self, dest: &mut T) {
        serde_json::to_string(self).unwrap().encode_to(dest)
    }
}

impl Decode for TrustedState {
    fn decode<I: Input>(value: &mut I) -> Result<Self, Error> {
        serde_json::from_str(&String::decode(value)?)
            .map_err(|_| "fail to decode trusted_state from json ".into())
    }
}

/// get genesis validator set
pub fn get_genesis_validators<C>(client: &C) -> CommonResult<validator::Set>
where
    C: Client,
{
    Ok(validator::Set::new(client.genesis()?.validators))
}
