#![allow(missing_docs)]
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct BroadcastTxResult {
    pub code: u8,
    pub data: String,
    pub hash: String,
    pub log: String,
}
