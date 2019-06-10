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
