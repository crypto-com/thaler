use secstr::SecUtf8;

use chain_core::common::H256;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use client_common::{Error, ErrorKind, Result, ResultExt, Storage};

use crate::service::{
    HDKeyService, KeyService, KeyServiceInterface, RootHashService, WalletService,
};
use crate::{SelectedUnspentTransactions, Signer};

/// Default implementation of `Signer`
#[derive(Debug, Clone)]
pub struct HDWalletSigner<S: Storage> {
    key_service: HDKeyService<S>,
    root_hash_service: RootHashService<S>,
    wallet_service: WalletService<S>,
}

impl<S> HDWalletSigner<S>
where
    S: Storage + Clone,
{
    /// Creates a new instance of default signer
    pub fn new(storage: S) -> Self {
        Self {
            key_service: HDKeyService::new(storage.clone()),
            root_hash_service: RootHashService::new(storage.clone()),
            wallet_service: WalletService::new(storage),
        }
    }
}

impl<S> HDWalletSigner<S>
where
    S: Storage,
{
    /// Signs the message with the private key corresponding to address of given output
    fn sign_with_output<T: AsRef<[u8]>>(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        message: T,
        output: &TxOut,
    ) -> Result<TxInWitness> {
        let root_hash = self
            .wallet_service
            .find_root_hash(name, passphrase, &output.address)?
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    format!(
                        "Output's address ({}) does not belong to wallet with name: {}",
                        output.address, name
                    ),
                )
            })?;

        self.sign_with_root_hash(passphrase, message, &root_hash)
    }

    /// Schnorr signs message with private key corresponding to `self_public_key` in given 1-of-n root hash
    fn sign_with_root_hash<T: AsRef<[u8]>>(
        &self,
        passphrase: &SecUtf8,
        message: T,
        root_hash: &H256,
    ) -> Result<TxInWitness> {
        if self
            .root_hash_service
            .required_signers(&root_hash, passphrase)?
            != 1
        {
            return Err(Error::new(
                ErrorKind::IllegalInput,
                "Default signer cannot sign with multi-sig addresses",
            ));
        }

        let public_key = self.root_hash_service.public_key(&root_hash, passphrase)?;
        let private_key = self
            .key_service
            .private_key(&public_key, passphrase)?
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
                .generate_proof(&root_hash, vec![public_key], passphrase)?;

        Ok(TxInWitness::TreeSig(
            private_key.schnorr_sign(&message)?,
            proof,
        ))
    }
}

impl<S> Signer for HDWalletSigner<S>
where
    S: Storage,
{
    fn sign<T: AsRef<[u8]>>(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        message: T,
        selected_unspent_transactions: SelectedUnspentTransactions<'_>,
    ) -> Result<TxWitness> {
        selected_unspent_transactions
            .iter()
            .map(|(_, output)| self.sign_with_output(name, passphrase, &message, output))
            .collect::<Result<Vec<TxInWitness>>>()
            .map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hdwallet_creation() {
        assert!(false);
    }
}
