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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_last_block_height() {
        let status = Status {
            sync_info: SyncInfo {
                latest_block_height: "2".to_owned(),
            },
        };

        assert_eq!(2, status.last_block_height().unwrap());
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
