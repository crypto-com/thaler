//! Wallet management
// #[cfg(feature = "sled")]
// mod sled_wallet;

// #[cfg(feature = "sled")]
// pub use self::sled_wallet::SledWallet;

#[cfg(all(feature = "sled", feature = "rpc"))]
mod rpc_sled_wallet_client;

#[cfg(all(feature = "sled", feature = "rpc"))]
pub use rpc_sled_wallet_client::RpcSledWalletClient;

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::balance::TransactionChange;
use client_common::Result;

use crate::PublicKey;

/// Interface for a generic wallet
pub trait WalletClient {
    /// Creates a new wallet with given name and returns wallet_id
    fn new_wallet(&self, name: &str, passphrase: &str) -> Result<String>;

    /// Retrieves all public keys corresponding to given wallet
    fn public_keys(&self, name: &str, passphrase: &str) -> Result<Vec<PublicKey>>;

    /// Retrieves all addresses corresponding to given wallet
    fn addresses(&self, name: &str, passphrase: &str) -> Result<Vec<ExtendedAddr>>;

    /// Generates a new public key for given wallet
    fn new_public_key(&self, name: &str, passphrase: &str) -> Result<PublicKey>;

    /// Generates a new address for given wallet
    fn new_address(&self, name: &str, passphrase: &str) -> Result<ExtendedAddr>;

    /// Retrieves current balance of wallet
    fn balance(&self, name: &str, passphrase: &str) -> Result<Coin>;

    /// Retrieves transaction history of wallet
    fn history(&self, name: &str, passphrase: &str) -> Result<Vec<TransactionChange>>;

    /// Synchronizes index with Crypto.com Chain (from last known height)
    fn sync(&self) -> Result<()>;

    /// Synchronizes index with Crypto.com Chain (from genesis)
    fn sync_all(&self) -> Result<()>;
}
