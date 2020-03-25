//! Type for specifying different wallet types
use std::str::FromStr;

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use unicase::eq_ascii;

use client_common::{Error, ErrorKind, Result};

/// Enum for specifying the kind of wallet (e.g., `Basic`, `HD`)
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub enum WalletKind {
    /// Basic Wallet
    Basic = 0,
    /// HD Wallet
    HD,
    /// HW Wallet
    HW,
}

impl From<u64> for WalletKind {
    fn from(code: u64) -> Self {
        match code {
            0 => WalletKind::Basic,
            1 => WalletKind::HD,
            _ => WalletKind::HW,
        }
    }
}

impl FromStr for WalletKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if eq_ascii(s, "hd") {
            Ok(WalletKind::HD)
        } else if eq_ascii(s, "hw") {
            Ok(WalletKind::HW)
        } else if eq_ascii(s, "basic") {
            Ok(WalletKind::Basic)
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Wallet type can either be `hd` or `hw` or `basic`",
            ))
        }
    }
}

impl Default for WalletKind {
    fn default() -> Self {
        WalletKind::Basic
    }
}
