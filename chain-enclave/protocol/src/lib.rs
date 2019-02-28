extern crate serde;
#[macro_use]
extern crate serde_derive;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum SubAbciRequest {
    InitChain(u8),
    // VerifyTX(TxAux)
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SubAbciResponse {
    InitChain(bool),
    UnknownRequest,
    // VerifyTX(TxAux)
}

pub const FLAGS: i32 = 0;