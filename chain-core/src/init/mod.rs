/// Eth-style address
pub mod address;
/// Fixed supply coin/amounts
pub mod coin;
/// Configuration in JSON passed to InitChain
pub mod config;

// maximum total supply with a fixed decimal point
pub const MAX_COIN: u64 = 100_000_000_000__000_000;
