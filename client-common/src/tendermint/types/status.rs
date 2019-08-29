#![allow(missing_docs)]

use failure::ResultExt;
use serde::Deserialize;

use crate::{ErrorKind, Result};

#[derive(Debug, Deserialize)]
pub struct Status {
    pub sync_info: SyncInfo,
}

#[derive(Debug, Deserialize)]
pub struct SyncInfo {
    pub latest_block_height: String,
    pub latest_app_hash: String,
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

    /// Returns last app hash
    #[inline]
    pub fn last_app_hash(&self) -> String {
        self.sync_info.latest_app_hash.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_last_block_height() {
        let status = Status {
            sync_info: SyncInfo {
                latest_block_height: "1".to_owned(),
                latest_app_hash: "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C"
                    .to_string(),
            },
        };
        assert_eq!(1, status.last_block_height().unwrap());
        assert_eq!(
            "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C".to_string(),
            status.last_app_hash()
        );
    }

    #[test]
    fn check_wrong_last_block_height() {
        let status = Status {
            sync_info: SyncInfo {
                latest_block_height: "a".to_owned(),
                latest_app_hash: "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C"
                    .to_string(),
            },
        };

        assert!(status.last_block_height().is_err());
        assert_eq!(
            "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C".to_string(),
            status.last_app_hash()
        );
    }
}
