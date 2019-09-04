#![allow(missing_docs)]
use base64::decode;
use serde::Deserialize;

use crate::{ErrorKind, Result, ResultExt};

#[derive(Debug, Deserialize)]
pub struct QueryResult {
    pub response: Response,
}

#[derive(Debug, Deserialize)]
pub struct Response {
    pub value: String,
}

impl QueryResult {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        Ok(decode(&self.response.value).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to decode base64 bytes on query result",
            )
        })?)
    }
}
