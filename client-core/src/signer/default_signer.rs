use either::Either;
use secstr::SecUtf8;

use chain_core::tx::witness::{TxInWitness, TxWitness};
use client_common::{ErrorKind, Result, Storage};

use crate::service::{KeyService, RootHashService, WalletService};
use crate::{SelectedUnspentTransactions, Signer};

/// Default implementation of `Signer`
#[derive(Debug)]
pub struct DefaultSigner<S: Storage> {
    key_service: KeyService<S>,
    root_hash_service: RootHashService<S>,
    wallet_service: WalletService<S>,
}

impl<S> DefaultSigner<S>
where
    S: Storage + Clone,
{
    /// Creates a new instance of default signer
    pub fn new(storage: S) -> Self {
        Self {
            key_service: KeyService::new(storage.clone()),
            root_hash_service: RootHashService::new(storage.clone()),
            wallet_service: WalletService::new(storage),
        }
    }
}

impl<S> Signer for DefaultSigner<S>
where
    S: Storage,
{
    fn sign<T: AsRef<[u8]>>(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        message: T,
        selected_unspent_transactions: SelectedUnspentTransactions,
    ) -> Result<TxWitness> {
        let mut witnesses = Vec::with_capacity(selected_unspent_transactions.len());

        for (_, output) in selected_unspent_transactions.iter() {
            match self
                .wallet_service
                .find(name, passphrase, &output.address)?
            {
                None => return Err(ErrorKind::AddressNotFound.into()),
                Some(Either::Left(public_key)) => {
                    match self.key_service.private_key(&public_key, passphrase)? {
                        None => return Err(ErrorKind::PrivateKeyNotFound.into()),
                        Some(private_key) => witnesses.push(private_key.sign(&message)?),
                    }
                }
                Some(Either::Right(root_hash)) => {
                    if self
                        .root_hash_service
                        .required_signers(&root_hash, passphrase)?
                        != 1
                    {
                        return Err(ErrorKind::InvalidTransaction.into());
                    }

                    let public_key = self.root_hash_service.public_key(&root_hash, passphrase)?;

                    match self.key_service.private_key(&public_key, passphrase)? {
                        None => return Err(ErrorKind::PrivateKeyNotFound.into()),
                        Some(private_key) => {
                            let proof = self.root_hash_service.generate_proof(
                                &root_hash,
                                vec![public_key],
                                passphrase,
                            )?;

                            witnesses.push(TxInWitness::TreeSig(
                                private_key.schnorr_sign(&message)?,
                                proof,
                            ));
                        }
                    }
                }
            }
        }

        Ok(witnesses.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chain_core::init::coin::Coin;
    use chain_core::tx::data::input::TxoPointer;
    use chain_core::tx::data::output::TxOut;
    use chain_core::tx::data::Tx;
    use chain_core::tx::TransactionId;
    use client_common::storage::MemoryStorage;

    use crate::wallet::DefaultWalletClient;
    use crate::{UnspentTransactions, WalletClient};

    #[test]
    fn check_redeem_signing_flow() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");
        let message = Tx::new().id();

        let storage = MemoryStorage::default();

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage.clone())
            .build()
            .unwrap();

        wallet_client.new_wallet(name, passphrase).unwrap();

        let redeem_addresses = vec![
            wallet_client.new_redeem_address(name, passphrase).unwrap(),
            wallet_client.new_redeem_address(name, passphrase).unwrap(),
            wallet_client.new_redeem_address(name, passphrase).unwrap(),
        ];

        let unspent_transactions = UnspentTransactions::new(vec![
            (
                TxoPointer::new([0; 32], 0),
                TxOut::new(redeem_addresses[0].clone(), Coin::zero()),
            ),
            (
                TxoPointer::new([1; 32], 0),
                TxOut::new(redeem_addresses[1].clone(), Coin::zero()),
            ),
            (
                TxoPointer::new([2; 32], 0),
                TxOut::new(redeem_addresses[2].clone(), Coin::zero()),
            ),
        ]);
        let selected_unspent_transactions = unspent_transactions.select_all();

        let signer = DefaultSigner::new(storage);

        let witness = signer
            .sign(name, passphrase, message, selected_unspent_transactions)
            .expect("Unable to sign transaction");

        assert!(witness[0]
            .verify_tx_address(&message, &redeem_addresses[0])
            .is_ok());
        assert!(witness[1]
            .verify_tx_address(&message, &redeem_addresses[1])
            .is_ok());
        assert!(witness[2]
            .verify_tx_address(&message, &redeem_addresses[2])
            .is_ok());
    }

    #[test]
    fn check_1_of_n_signing_flow() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");
        let message = Tx::new().id();

        let storage = MemoryStorage::default();

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage.clone())
            .build()
            .unwrap();

        wallet_client.new_wallet(name, passphrase).unwrap();

        let public_keys = vec![
            wallet_client.new_public_key(name, passphrase).unwrap(),
            wallet_client.new_public_key(name, passphrase).unwrap(),
            wallet_client.new_public_key(name, passphrase).unwrap(),
        ];

        let tree_address = wallet_client
            .new_tree_address(
                name,
                passphrase,
                public_keys.clone(),
                public_keys[0].clone(),
                1,
                3,
            )
            .unwrap();

        let unspent_transactions = UnspentTransactions::new(vec![(
            TxoPointer::new([0; 32], 0),
            TxOut::new(tree_address.clone(), Coin::zero()),
        )]);
        let selected_unspent_transactions = unspent_transactions.select_all();

        let signer = DefaultSigner::new(storage);

        let witness = signer
            .sign(name, passphrase, message, selected_unspent_transactions)
            .expect("Unable to sign transaction");

        assert!(witness[0]
            .verify_tx_address(&message, &tree_address)
            .is_ok());
    }

    #[test]
    fn check_2_of_3_invalid_signing_flow() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");
        let message = Tx::new().id();

        let storage = MemoryStorage::default();

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage.clone())
            .build()
            .unwrap();

        wallet_client.new_wallet(name, passphrase).unwrap();

        let public_keys = vec![
            wallet_client.new_public_key(name, passphrase).unwrap(),
            wallet_client.new_public_key(name, passphrase).unwrap(),
            wallet_client.new_public_key(name, passphrase).unwrap(),
        ];

        let tree_address = wallet_client
            .new_tree_address(
                name,
                passphrase,
                public_keys.clone(),
                public_keys[0].clone(),
                2,
                3,
            )
            .unwrap();

        let unspent_transactions = UnspentTransactions::new(vec![(
            TxoPointer::new([0; 32], 0),
            TxOut::new(tree_address.clone(), Coin::zero()),
        )]);
        let selected_unspent_transactions = unspent_transactions.select_all();

        let signer = DefaultSigner::new(storage);

        assert_eq!(
            ErrorKind::InvalidTransaction,
            signer
                .sign(name, passphrase, message, selected_unspent_transactions)
                .expect_err("Unable to sign transaction")
                .kind()
        );
    }
}
