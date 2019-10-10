use client_common::{Error, ErrorKind, Result};
use std::str::FromStr;
use unicase::eq_ascii;
/// Wallet kinds
/// Basic: default wallet
/// HD: HD wallet
/// Hardware: hardware based wallets
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum WalletKind {
    /// Basic Wallet
    Basic,
    /// HD Wallet
    HD,
}

impl FromStr for WalletKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if eq_ascii(s, "hd") {
            Ok(WalletKind::HD)
        } else if eq_ascii(s, "basic") {
            Ok(WalletKind::Basic)
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Wallet type can either be `hd` or `basic`",
            ))
        }
    }
}

impl Default for WalletKind {
    fn default() -> Self {
        WalletKind::Basic
    }
}
