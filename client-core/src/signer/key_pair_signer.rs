//! A signer that sign message using the provided key pair
use chain_core::common::Proof;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::witness::tree::RawPubkey;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use client_common::{Error, ErrorKind, MultiSigAddress, PrivateKey, PublicKey, Result, ResultExt};

use crate::{SelectedUnspentTransactions, SignCondition, Signer};

/// Signer using key pair
pub struct KeyPairSigner {
    extended_addr: ExtendedAddr,
    proof: Proof<RawPubkey>,
    private_key: PrivateKey,
}

impl KeyPairSigner {
    /// Create a new signer using the provided key pair
    #[inline]
    pub fn new(private_key: PrivateKey, public_key: PublicKey) -> Result<Self> {
        let (extended_addr, proof) = generate_extended_addr_and_proof(public_key)?;
        Ok(KeyPairSigner {
            extended_addr,
            proof,
            private_key,
        })
    }
}

fn generate_extended_addr_and_proof(
    public_key: PublicKey,
) -> Result<(ExtendedAddr, Proof<RawPubkey>)> {
    let require_signers = 1;
    let multi_sig_address = MultiSigAddress::new(
        vec![public_key.clone()],
        public_key.clone(),
        require_signers,
    )?;
    let proof = multi_sig_address
        .generate_proof(vec![public_key])?
        .chain(|| (ErrorKind::InvalidInput, "Unable to generate merkle proof"))?;
    let extended_addr = ExtendedAddr::from(multi_sig_address);

    Ok((extended_addr, proof))
}

impl Signer for KeyPairSigner {
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
        if *signing_addr == self.extended_addr {
            Ok(SignCondition::SingleSignUnlock)
        } else {
            Ok(SignCondition::Impossible)
        }
    }
    fn schnorr_sign<T: AsRef<[u8]>>(
        &self,
        message: T,
        signing_addr: &ExtendedAddr,
    ) -> Result<TxInWitness> {
        if *signing_addr != self.extended_addr {
            return Err(Error::new(
                ErrorKind::MultiSigError,
                "Signing address does not belong to the key pair",
            ));
        }

        Ok(TxInWitness::TreeSig(
            self.private_key.schnorr_sign(&message)?,
            self.proof.clone(),
        ))
    }
}
