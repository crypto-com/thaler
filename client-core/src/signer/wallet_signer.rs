//! Wallet signer responsible for signing as wallet
use chain_core::common::H256;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use client_common::{Error, ErrorKind, Result, ResultExt, SecKey, Storage};

use crate::service::{KeyService, RootHashService, WalletService};
use crate::{SelectedUnspentTransactions, SignCondition, Signer};

/// Wallet signer manager responsible for creating wallet signers
#[derive(Debug, Clone)]
pub struct WalletSignerManager<S>
where
    S: Storage,
{
    key_service: KeyService<S>,
    root_hash_service: RootHashService<S>,
    wallet_service: WalletService<S>,
}

impl<S> WalletSignerManager<S>
where
    S: Storage,
{
    /// Create an instance fo wallet signer manager
    pub fn new(storage: S) -> Self {
        Self {
            key_service: KeyService::new(storage.clone()),
            root_hash_service: RootHashService::new(storage.clone()),
            wallet_service: WalletService::new(storage),
        }
    }

    /// Create an instance of wallet signer
    pub fn create_signer<'a>(&'a self, name: &'a str, enckey: &'a SecKey) -> WalletSigner<'a, S> {
        WalletSigner::new(
            name,
            enckey,
            &self.key_service,
            &self.root_hash_service,
            &self.wallet_service,
        )
    }
}

/// A short-lived signer belonging to a wallet
pub struct WalletSigner<'a, S>
where
    S: Storage,
{
    name: &'a str,
    enckey: &'a SecKey,
    key_service: &'a KeyService<S>,
    root_hash_service: &'a RootHashService<S>,
    wallet_service: &'a WalletService<S>,
}

impl<'a, S> WalletSigner<'a, S>
where
    S: Storage,
{
    /// Create an instance of wallet signer
    pub fn new(
        name: &'a str,
        enckey: &'a SecKey,
        key_service: &'a KeyService<S>,
        root_hash_service: &'a RootHashService<S>,
        wallet_service: &'a WalletService<S>,
    ) -> Self {
        WalletSigner {
            name,
            enckey,
            key_service,
            root_hash_service,
            wallet_service,
        }
    }
}

impl<'a, S> Signer for WalletSigner<'a, S>
where
    S: Storage,
{
    fn schnorr_sign_transaction<T: AsRef<[u8]>>(
        &self,
        message: T,
        selected_unspent_transactions: &SelectedUnspentTransactions<'_>,
    ) -> Result<TxWitness> {
        selected_unspent_transactions
            .iter()
            .map(|(_, output)| self.schnorr_sign(&message, &output.address))
            .collect::<Result<Vec<TxInWitness>>>()
            .map(Into::into)
    }

    fn schnorr_sign_condition(&self, signing_addr: &ExtendedAddr) -> Result<SignCondition> {
        let maybe_root_hash =
            self.wallet_service
                .find_root_hash(self.name, self.enckey, signing_addr)?;
        if None == maybe_root_hash {
            Ok(SignCondition::Impossible)
        } else {
            Ok(SignCondition::SingleSignUnlock)
        }
    }

    fn schnorr_sign<T: AsRef<[u8]>>(
        &self,
        message: T,
        signing_addr: &ExtendedAddr,
    ) -> Result<TxInWitness> {
        let root_hash = self
            .wallet_service
            .find_root_hash(self.name, self.enckey, signing_addr)?
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    format!(
                        "Output's address ({}) does not belong to wallet with name: {}",
                        signing_addr, self.name
                    ),
                )
            })?;

        self.schnorr_sign_with_root_hash(message, &root_hash)
    }
}

impl<'a, S> WalletSigner<'a, S>
where
    S: Storage,
{
    /// Schnorr signs message with private key corresponding to `self_public_key` in given 1-of-n root hash
    fn schnorr_sign_with_root_hash<T: AsRef<[u8]>>(
        &self,
        message: T,
        root_hash: &H256,
    ) -> Result<TxInWitness> {
        if self
            .root_hash_service
            .required_signers(&root_hash, self.enckey)?
            != 1
        {
            return Err(Error::new(
                ErrorKind::IllegalInput,
                "Default signer cannot sign with multi-sig addresses",
            ));
        }

        let public_key = self.root_hash_service.public_key(&root_hash, self.enckey)?;
        let private_key = self
            .key_service
            .private_key(&public_key, self.enckey)?
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    format!(
                        "Unable to find private key corresponding to given root hash: {}",
                        hex::encode(root_hash)
                    ),
                )
            })?;

        let proof =
            self.root_hash_service
                .generate_proof(&root_hash, vec![public_key], self.enckey)?;

        Ok(TxInWitness::TreeSig(
            private_key.schnorr_sign(&message)?,
            proof,
        ))
    }
}

#[cfg(test)]
mod wallet_signer_tests {
    use super::*;
    use secstr::SecUtf8;

    use chain_core::tx::data::Tx;
    use chain_core::tx::TransactionId;
    use chain_tx_validation::witness::verify_tx_address;
    use client_common::storage::MemoryStorage;

    use crate::types::WalletKind;
    use crate::wallet::{DefaultWalletClient, WalletClient};

    #[test]
    fn check_1_of_n_signing_flow() {
        let name = "name";
        let passphrase = SecUtf8::from("passphrase");
        let message = Tx::new().id();

        let storage = MemoryStorage::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let (enckey, _) = wallet_client
            .new_wallet(name, &passphrase, WalletKind::Basic)
            .unwrap();

        let public_keys = vec![
            wallet_client.new_public_key(name, &enckey, None).unwrap(),
            wallet_client.new_public_key(name, &enckey, None).unwrap(),
            wallet_client.new_public_key(name, &enckey, None).unwrap(),
        ];

        let tree_address = wallet_client
            .new_multisig_transfer_address(
                name,
                &enckey,
                public_keys.clone(),
                public_keys[0].clone(),
                1,
            )
            .unwrap();

        let signer_manager = WalletSignerManager::new(storage);
        let signer = signer_manager.create_signer(name, &enckey);

        let witness = signer
            .schnorr_sign(message, &tree_address)
            .expect("Unable to sign transaction");

        assert!(verify_tx_address(&witness, &message, &tree_address).is_ok());
    }

    #[test]
    fn check_2_of_3_invalid_signing_flow() {
        let name = "name";
        let passphrase = SecUtf8::from("passphrase");
        let message = Tx::new().id();

        let storage = MemoryStorage::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let (enckey, _) = wallet_client
            .new_wallet(name, &passphrase, WalletKind::Basic)
            .unwrap();

        let public_keys = vec![
            wallet_client.new_public_key(name, &enckey, None).unwrap(),
            wallet_client.new_public_key(name, &enckey, None).unwrap(),
            wallet_client.new_public_key(name, &enckey, None).unwrap(),
        ];

        let tree_address = wallet_client
            .new_multisig_transfer_address(
                name,
                &enckey,
                public_keys.clone(),
                public_keys[0].clone(),
                2,
            )
            .unwrap();

        let signer_manager = WalletSignerManager::new(storage);
        let signer = signer_manager.create_signer(name, &enckey);

        assert_eq!(
            ErrorKind::IllegalInput,
            signer
                .schnorr_sign(message, &tree_address)
                .expect_err("Unable to sign transaction")
                .kind()
        );
    }
}
