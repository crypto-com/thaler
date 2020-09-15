use crate::hd_wallet::ChainPath;
use crate::service::ledger_service::LedgerServiceHID;
#[cfg(feature = "mock-hardware-wallet")]
use crate::service::ledger_service::LedgerServiceZemu;
use client_common::{ErrorKind, PrivateKeyAction, PublicKey, Result};

/// collection of hardware key interfaces
pub trait HardwareWalletAction: Send + Sync + Clone {
    /// get the public key by a given ChainPath
    fn get_public_key(&self, _chain_path: ChainPath) -> Result<PublicKey> {
        Err(ErrorKind::PermissionDenied.into())
    }
    /// return a private key action object
    fn get_sign_key(&self, _hd_path: &ChainPath) -> Result<Box<dyn PrivateKeyAction>> {
        Err(ErrorKind::PermissionDenied.into())
    }
}

/// unauthorized hardware key service
#[derive(Clone, Debug)]
pub struct UnauthorizedHwKeyService;
impl HardwareWalletAction for UnauthorizedHwKeyService {}

/// Hardware Key Service collections
/// TODO: add Ledger, Trezor Service
#[derive(Clone, Debug)]
pub enum HwKeyService {
    /// unauthorized hardware key service
    Unauthorized(UnauthorizedHwKeyService),
    /// mock key service
    #[cfg(feature = "mock-hardware-wallet")]
    Mock(LedgerServiceZemu),
    /// ledger service
    Ledger(LedgerServiceHID),
}

impl Default for HwKeyService {
    fn default() -> Self {
        Self::Unauthorized(UnauthorizedHwKeyService)
    }
}

impl HwKeyService {
    /// return a private key action object
    pub fn get_sign_key(&self, hd_path: &ChainPath) -> Result<Box<dyn PrivateKeyAction>> {
        match self {
            HwKeyService::Unauthorized(hw_key_service) => hw_key_service.get_sign_key(hd_path),
            #[cfg(feature = "mock-hardware-wallet")]
            HwKeyService::Mock(hw_key_service) => hw_key_service.get_sign_key(hd_path),
            HwKeyService::Ledger(ledger_service) => ledger_service.get_sign_key(hd_path),
        }
    }

    /// return a public key
    pub fn get_public_key(&self, chain_path: ChainPath) -> Result<PublicKey> {
        match self {
            HwKeyService::Unauthorized(hw_key_service) => hw_key_service.get_public_key(chain_path),
            #[cfg(feature = "mock-hardware-wallet")]
            HwKeyService::Mock(hw_key_service) => hw_key_service.get_public_key(chain_path),
            HwKeyService::Ledger(ledger_service) => ledger_service.get_public_key(chain_path),
        }
    }
}
