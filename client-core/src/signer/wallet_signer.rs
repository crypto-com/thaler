//! Wallet signer responsible for signing as wallet
use chain_core::common::H256;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use client_common::Transaction;
use client_common::{Error, ErrorKind, Result, ResultExt, SecKey, Storage};

use crate::service::{HwKeyService, KeyService, RootHashService, WalletService};
use crate::types::WalletKind;
use crate::{SelectedUnspentTransactions, SignCondition, Signer};

/// Wallet signer manager responsible for creating wallet signers
#[derive(Debug, Clone)]
pub struct WalletSignerManager<S>
where
    S: Storage,
{
    /// hardware key serivce
    pub hw_key_service: HwKeyService,
    key_service: KeyService<S>,
    root_hash_service: RootHashService<S>,
    wallet_service: WalletService<S>,
}

impl<S> WalletSignerManager<S>
where
    S: Storage,
{
    /// Create an instance fo wallet signer manager
    pub fn new(storage: S, hw_key_service: HwKeyService) -> Self {
        Self {
            hw_key_service,
            key_service: KeyService::new(storage.clone()),
            root_hash_service: RootHashService::new(storage.clone()),
            wallet_service: WalletService::new(storage),
        }
    }

    /// Create an instance of wallet signer
    pub fn create_signer<'a>(
        &'a self,
        name: &'a str,
        enckey: &'a SecKey,
        hw_key_service: &'a HwKeyService,
    ) -> WalletSigner<'a, S> {
        WalletSigner::new(
            name,
            enckey,
            &self.root_hash_service,
            &self.wallet_service,
            hw_key_service,
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
    root_hash_service: &'a RootHashService<S>,
    wallet_service: &'a WalletService<S>,
    hw_key_service: &'a HwKeyService,
}

impl<'a, S> WalletSigner<'a, S>
where
    S: Storage,
{
    /// Create an instance of wallet signer
    pub fn new(
        name: &'a str,
        enckey: &'a SecKey,
        root_hash_service: &'a RootHashService<S>,
        wallet_service: &'a WalletService<S>,
        hw_key_service: &'a HwKeyService,
    ) -> Self {
        WalletSigner {
            name,
            enckey,
            root_hash_service,
            wallet_service,
            hw_key_service,
        }
    }
}

impl<'a, S> Signer for WalletSigner<'a, S>
where
    S: Storage,
{
    fn schnorr_sign_transaction(
        &self,
        tx: &Transaction,
        selected_unspent_transactions: &SelectedUnspentTransactions<'_>,
    ) -> Result<TxWitness> {
        selected_unspent_transactions
            .iter()
            .map(|(_, output)| self.schnorr_sign(tx, &output.address))
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

    fn schnorr_sign(&self, tx: &Transaction, signing_addr: &ExtendedAddr) -> Result<TxInWitness> {
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

        self.schnorr_sign_with_root_hash(tx, &root_hash)
    }
}

impl<'a, S> WalletSigner<'a, S>
where
    S: Storage,
{
    /// Schnorr signs message with private key corresponding to `self_public_key` in given 1-of-n root hash
    fn schnorr_sign_with_root_hash(
        &self,
        tx: &Transaction,
        root_hash: &H256,
    ) -> Result<TxInWitness> {
        if self
            .root_hash_service
            .required_signers(self.name, &root_hash, self.enckey)?
            != 1
        {
            return Err(Error::new(
                ErrorKind::IllegalInput,
                "Default signer cannot sign with multi-sig addresses",
            ));
        }

        let public_key = self
            .root_hash_service
            .public_key(self.name, &root_hash, self.enckey)?;
        let wallet = self.wallet_service.get_wallet(self.name, self.enckey)?;
        let sign_key = match wallet.wallet_kind {
            WalletKind::HW => self.hw_key_service.get_sign_key(&public_key)?,
            WalletKind::Basic | WalletKind::HD => {
                let private_key = self
                    .wallet_service
                    .find_private_key(self.name, self.enckey, &public_key)?
                    .chain(|| {
                        (
                            ErrorKind::InvalidInput,
                            format!(
                                "Unable to find private key corresponding to given root hash: {}",
                                hex::encode(root_hash)
                            ),
                        )
                    })?;
                Box::new(private_key)
            }
        };

        let proof = self.root_hash_service.generate_proof(
            self.name,
            &root_hash,
            vec![public_key],
            self.enckey,
        )?;

        Ok(TxInWitness::TreeSig(sign_key.schnorr_sign(tx)?, proof))
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
        let tx = Transaction::TransferTransaction(Tx::new());

        let storage = MemoryStorage::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let (enckey, _) = wallet_client
            .new_wallet(name, &passphrase, WalletKind::Basic, None)
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
        let hw_key_service = HwKeyService::default();
        let signer_manager = WalletSignerManager::new(storage, hw_key_service.clone());
        let signer = signer_manager.create_signer(name, &enckey, &hw_key_service);

        let witness = signer
            .schnorr_sign(&tx, &tree_address)
            .expect("Unable to sign transaction");

        assert!(verify_tx_address(&witness, &tx.id(), &tree_address).is_ok());
    }

    #[test]
    fn check_2_of_3_invalid_signing_flow() {
        let name = "name";
        let passphrase = SecUtf8::from("passphrase");
        let tx = Transaction::TransferTransaction(Tx::new());

        let storage = MemoryStorage::default();

        let wallet_client = DefaultWalletClient::new_read_only(storage.clone());

        let (enckey, _) = wallet_client
            .new_wallet(name, &passphrase, WalletKind::Basic, None)
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

        let hw_key_service = HwKeyService::default();
        let signer_manager = WalletSignerManager::new(storage, hw_key_service.clone());
        let signer = signer_manager.create_signer(name, &enckey, &hw_key_service);

        assert_eq!(
            ErrorKind::IllegalInput,
            signer
                .schnorr_sign(&tx, &tree_address)
                .expect_err("Unable to sign transaction")
                .kind()
        );
    }
}
