// clippy disabled for easier visual verification of decimals in MAX_COIN
#![allow(clippy::inconsistent_digit_grouping)]

/// Eth-style address
pub mod address;
/// Fixed supply coin/amounts
pub mod coin;
/// Configuration in JSON passed to InitChain
#[cfg(feature = "base64")]
pub mod config;

/// Network static configuration
#[cfg(all(feature = "bech32", feature = "hex"))]
pub mod network;

/// Network parameters
pub mod params;

/// maximum total supply with a fixed decimal point
/// ref: https://etherscan.io/token/0xa0b73e1ff0b80914ab6fe0444e65848c4c34450b
/// 100 billion + 8 decimals
pub const MAX_COIN: u64 = 100_000_000_000__0000_0000;
/// 8 decimals => div/mod 1_0000_0000
pub const MAX_COIN_DECIMALS: u64 = 1_0000_0000;
/// 100 billion
pub const MAX_COIN_UNITS: i64 = 100_000_000_000;
