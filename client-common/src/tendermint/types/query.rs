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
    #[serde(default)]
    pub code: u8,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub log: String,
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

    #[inline]
    pub fn code(&self) -> u8 {
        self.response.code
    }

    #[inline]
    pub fn log(&self) -> &str {
        &self.response.log
    }
}
