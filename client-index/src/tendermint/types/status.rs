#![allow(missing_docs)]

use failure::ResultExt;
use serde::{Deserialize, Serialize};

use client_common::{ErrorKind, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    sync_info: SyncInfo,
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncInfo {
    latest_block_height: String,
}

impl Status {
    /// Returns last block height
    pub fn last_block_height(&self) -> Result<u64> {
        Ok(self
            .sync_info
            .latest_block_height
            .parse::<u64>()
            .context(ErrorKind::DeserializationError)?)
    }
}

// Note: Do not change these values. These are tied with tests for `RpcSledIndex`
#[cfg(test)]
impl Default for Status {
    fn default() -> Self {
        Status {
            sync_info: SyncInfo {
                latest_block_height: "1".to_owned(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_last_block_height() {
        let status = Status::default();
        assert_eq!(1, status.last_block_height().unwrap());
    }

    #[test]
    fn check_wrong_last_block_height() {
        let status = Status {
            sync_info: SyncInfo {
                latest_block_height: "a".to_owned(),
            },
        };

        assert!(status.last_block_height().is_err());
    }
}
