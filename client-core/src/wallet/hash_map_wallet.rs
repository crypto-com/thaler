#![cfg(any(test, feature = "hash-map"))]
use crate::service::{KeyService, WalletService};
use crate::storage::HashMapStorage;
use crate::Wallet;

/// Wallet backed by [`HashMapStorage`](crate::storage::HashMapStorage)
#[derive(Default)]
pub struct HashMapWallet {
    key_service: KeyService<HashMapStorage>,
    wallet_service: WalletService<HashMapStorage>,
}

impl Wallet<HashMapStorage, HashMapStorage> for HashMapWallet {
    fn key_service(&self) -> &KeyService<HashMapStorage> {
        &self.key_service
    }

    fn wallet_service(&self) -> &WalletService<HashMapStorage> {
        &self.wallet_service
    }
}

#[cfg(test)]
mod tests {
    use super::HashMapWallet;
    use crate::Wallet;

    #[test]
    fn check_happy_flow() {
        let wallet = HashMapWallet::default();

        wallet
            .new_wallet("name", "passphrase")
            .expect("Unable to create a new wallet");

        assert_eq!(
            None,
            wallet
                .get_addresses("name", "passphrase")
                .expect("Unable to retrieve addresses"),
            "Wallet already has keys"
        );

        let address = wallet
            .generate_address("name", "passphrase")
            .expect("Unable to generate new address");

        let addresses = wallet
            .get_addresses("name", "passphrase")
            .expect("Unable to retrieve addresses")
            .expect("No addresses found");

        assert_eq!(1, addresses.len(), "Invalid addresses length");
        assert_eq!(address, addresses[0], "Addresses don't match");
    }
}
