#![allow(missing_docs)]
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct QueryResult {
    pub response: Response,
}

#[derive(Debug, Deserialize)]
pub struct Response {
    pub value: String,
}
