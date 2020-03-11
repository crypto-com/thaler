#[cfg(feature = "mock-hardware-wallet")]
use client_core::service::MockHardwareWallet;

fn main() {
    env_logger::init();
    #[cfg(feature = "mock-hardware-wallet")]
    {
        let mut hw_wallet = MockHardwareWallet::new();
        hw_wallet.run()
    }
}
