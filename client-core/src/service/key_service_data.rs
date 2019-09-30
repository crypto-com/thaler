use secstr::SecUtf8;
use zeroize::Zeroize;

use client_common::{PrivateKey, PublicKey, Result, SecureStorage, Storage};
use std::sync::Once;
static INIT_WALLET: Once = Once::new();

/// Wallet kinds
/// Basic: default wallet
/// HD: HD wallet
/// Hardware: hardware based wallets
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum WalletKinds {
    /// Basic Wallet
    Basic,
    /// HD Wallet
    HD,
    /// Hardware Wallet
    Hardware,
}

impl Default for WalletKinds {
    fn default() -> Self {
        WalletKinds::Basic
    }
}

/// key service interface
pub trait KeyServiceInterface {
    /// Generates a new public-private keypair
    fn generate_keypair(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        is_staking: bool,
    ) -> Result<(PublicKey, PrivateKey)>;
    /// Retrieves private key corresponding to given public key
    fn private_key(
        &self,
        public_key: &PublicKey,
        passphrase: &SecUtf8,
    ) -> Result<Option<PrivateKey>>;
    /// Clears all storage
    fn clear(&self) -> Result<()>;
}
