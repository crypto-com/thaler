//! Management services
mod hd_key_service;
mod hw_key_service;
mod key_service;
#[cfg(feature = "mock-hardware-wallet")]
mod mock_hw_key_service;
#[cfg(feature = "experimental")]
mod multi_sig_session_service;
mod root_hash_service;
mod sync_state_service;
mod wallet_service;
mod wallet_state_service;

#[doc(hidden)]
pub use self::wallet_state_service::WalletStateMemento;

pub use self::hd_key_service::{HDAccountType, HdKey, HdKeyService};
pub use self::hw_key_service::{HwKeyService, UnauthorizedHwKeyService};
pub use self::key_service::KeyService;
#[cfg(feature = "mock-hardware-wallet")]
pub use self::mock_hw_key_service::{MockHardwareKey, MockHardwareService, MockHardwareWallet};
#[cfg(feature = "experimental")]
pub use self::multi_sig_session_service::MultiSigSessionService;
pub use self::root_hash_service::RootHashService;
pub use self::sync_state_service::{
    delete_sync_state, load_sync_state, save_sync_state, SyncState, SyncStateService,
};
pub use self::wallet_service::{load_wallet, Wallet, WalletInfo, WalletService};
pub use self::wallet_state_service::{
    delete_wallet_state, load_wallet_state, modify_wallet_state, save_wallet_state, WalletState,
    WalletStateService,
};
