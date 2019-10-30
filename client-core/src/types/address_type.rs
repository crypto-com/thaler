use std::str::FromStr;

use unicase::eq_ascii;

use client_common::{Error, ErrorKind, Result};

/// Enum for specifying different types of addresses
#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    /// Transfer address
    Transfer,
    /// Staking address
    Staking,
}

impl FromStr for AddressType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if eq_ascii(s, "transfer") {
            Ok(AddressType::Transfer)
        } else if eq_ascii(s, "staking") {
            Ok(AddressType::Staking)
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Address type can either be `transfer` or `staking`",
            ))
        }
    }
}

impl Default for AddressType {
    fn default() -> Self {
        Self::Transfer
    }
}
