#![cfg(feature = "sled")]

use std::path::Path;

use crate::service::{KeyService, WalletService};
use crate::storage::SledStorage;
use crate::{Result, Wallet};

const KEY_PATH: &str = "key";
const WALLET_PATH: &str = "wallet";

/// Wallet backed by [`SledStorage`](crate::storage::SledStorage)
pub struct SledWallet {
    key_service: KeyService<SledStorage>,
    wallet_service: WalletService<SledStorage>,
}

impl SledWallet {
    /// Creates a new instance with specified path for data storage
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut path_buf = path.as_ref().to_path_buf();
        path_buf.push(KEY_PATH);

        let key_storage = SledStorage::new(path_buf.as_path())?;
        let key_service = KeyService::new(key_storage);

        path_buf.pop();
        path_buf.push(WALLET_PATH);

        let wallet_storage = SledStorage::new(path_buf.as_path())?;
        let wallet_service = WalletService::new(wallet_storage);

        Ok(SledWallet {
            key_service,
            wallet_service,
        })
    }
}

impl Wallet<SledStorage, SledStorage> for SledWallet {
    fn key_service(&self) -> &KeyService<SledStorage> {
        &self.key_service
    }

    fn wallet_service(&self) -> &WalletService<SledStorage> {
        &self.wallet_service
    }
}
