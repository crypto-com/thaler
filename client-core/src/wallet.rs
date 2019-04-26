//! Wallet management
mod default_wallet_client;

pub use default_wallet_client::DefaultWalletClient;

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use client_common::balance::TransactionChange;
use client_common::Result;

use crate::{PrivateKey, PublicKey};

/// Interface for a generic wallet
pub trait WalletClient: Send + Sync {
    /// Retrieves names of all wallets stored
    fn wallets(&self) -> Result<Vec<String>>;

    /// Creates a new wallet with given name and returns wallet_id
    fn new_wallet(&self, name: &str, passphrase: &str) -> Result<String>;

    /// Retrieves all public keys corresponding to given wallet
    fn private_keys(&self, name: &str, passphrase: &str) -> Result<Vec<PrivateKey>>;

    /// Retrieves all public keys corresponding to given wallet
    fn public_keys(&self, name: &str, passphrase: &str) -> Result<Vec<PublicKey>>;

    /// Retrieves all addresses corresponding to given wallet
    fn addresses(&self, name: &str, passphrase: &str) -> Result<Vec<ExtendedAddr>>;

    /// Retrieves private key corresponding to given address
    fn private_key(
        &self,
        name: &str,
        passphrase: &str,
        address: &ExtendedAddr,
    ) -> Result<Option<PrivateKey>>;

    /// Generates a new public key for given wallet
    fn new_public_key(&self, name: &str, passphrase: &str) -> Result<PublicKey>;

    /// Generates a new address for given wallet
    fn new_address(&self, name: &str, passphrase: &str) -> Result<ExtendedAddr>;

    /// Retrieves current balance of wallet
    fn balance(&self, name: &str, passphrase: &str) -> Result<Coin>;

    /// Retrieves transaction history of wallet
    fn history(&self, name: &str, passphrase: &str) -> Result<Vec<TransactionChange>>;

    /// Creates and broadcasts a transaction to Crypto.com Chain
    fn create_and_broadcast_transaction(
        &self,
        name: &str,
        passphrase: &str,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
    ) -> Result<()>;

    /// Broadcasts a transaction to Crypto.com Chain
    fn broadcast_transaction(&self, name: &str, passphrase: &str, transaction: Tx) -> Result<()>;

    /// Synchronizes index with Crypto.com Chain (from last known height)
    fn sync(&self) -> Result<()>;

    /// Synchronizes index with Crypto.com Chain (from genesis)
    fn sync_all(&self) -> Result<()>;
}
