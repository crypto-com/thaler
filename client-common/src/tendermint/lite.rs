//! Lite tendermint client
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::{Deserialize, Serialize};
use tendermint::{block::signed_header::SignedHeader, block::Header, lite, validator};

use crate::tendermint::client::Client;
use crate::Result as CommonResult;

///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustedState(pub(crate) Option<lite::TrustedState<SignedHeader, Header>>);

impl TrustedState {
    /// construct genesis trusted state
    pub fn genesis(_genesis_validators: Vec<validator::Info>) -> TrustedState {
        // FIXME verify the first block against genesis block.
        TrustedState(None)
    }
}

impl From<lite::TrustedState<SignedHeader, Header>> for TrustedState {
    fn from(state: lite::TrustedState<SignedHeader, Header>) -> TrustedState {
        TrustedState(Some(state))
    }
}

impl Encode for TrustedState {
    fn encode_to<T: Output>(&self, dest: &mut T) {
        serde_json::to_string(&self.0).unwrap().encode_to(dest)
    }
}

impl Decode for TrustedState {
    fn decode<I: Input>(value: &mut I) -> Result<Self, Error> {
        serde_json::from_str(&String::decode(value)?)
            .map_err(|_| "fail to decode trusted_state from json ".into())
            .map(TrustedState)
    }
}

/// get genesis validator set
pub fn get_genesis_validators<C>(client: &C) -> CommonResult<validator::Set>
where
    C: Client,
{
    Ok(validator::Set::new(client.genesis()?.validators))
}
