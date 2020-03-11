#[cfg(feature = "mock-hardware-wallet")]
use crate::service::MockHardwareService;
use client_common::{ErrorKind, PrivateKeyAction, PublicKey, Result};

/// collection of hardware key interfaces
pub trait HardwareWalletAction: Send + Sync + Clone {
    /// create a new transfer address, return the public key
    fn new_transfer_address(&self) -> Result<PublicKey> {
        Err(ErrorKind::PermissionDenied.into())
    }

    /// create a new staking address, return the public key
    fn new_staking_address(&self) -> Result<PublicKey> {
        Err(ErrorKind::PermissionDenied.into())
    }

    /// return a private key action object
    fn get_sign_key(&self, _public_key: &PublicKey) -> Result<Box<dyn PrivateKeyAction>> {
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
    Mock(MockHardwareService),
}

impl Default for HwKeyService {
    fn default() -> Self {
        Self::Unauthorized(UnauthorizedHwKeyService)
    }
}

impl HwKeyService {
    /// create a new transfer address, return the public key
    pub fn new_transfer_address(&self) -> Result<PublicKey> {
        match self {
            HwKeyService::Unauthorized(hw_key_service) => hw_key_service.new_staking_address(),
            #[cfg(feature = "mock-hardware-wallet")]
            HwKeyService::Mock(hw_key_service) => hw_key_service.new_transfer_address(),
        }
    }

    /// create a new staking address, return the public key
    pub fn new_staking_address(&self) -> Result<PublicKey> {
        match self {
            HwKeyService::Unauthorized(hw_key_service) => hw_key_service.new_transfer_address(),
            #[cfg(feature = "mock-hardware-wallet")]
            HwKeyService::Mock(hw_key_service) => hw_key_service.new_staking_address(),
        }
    }

    /// return a private key action object
    pub fn get_sign_key(&self, public_key: &PublicKey) -> Result<Box<dyn PrivateKeyAction>> {
        match self {
            HwKeyService::Unauthorized(hw_key_service) => hw_key_service.get_sign_key(public_key),
            #[cfg(feature = "mock-hardware-wallet")]
            HwKeyService::Mock(hw_key_service) => hw_key_service.get_sign_key(public_key),
        }
    }
}
