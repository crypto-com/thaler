use parity_scale_codec::{Decode, Encode};

use chain_core::common::H256;
use client_common::{Error, ErrorKind, PublicKey, Result};

/// Individual MultiSig signer data
#[derive(Debug, Encode, Decode)]
pub struct Signer {
    /// Public key of signer
    pub public_key: PublicKey,
    /// Nonce commitment of signer (when available)
    pub nonce_commitment: Option<H256>,
    /// Nonce of signer (when available)
    pub nonce: Option<PublicKey>,
    /// Partial signature of signer (when available)
    pub partial_signature: Option<H256>,
}

impl Signer {
    /// Adds nonce commitment to current signer if not already added.
    pub fn add_nonce_commitment(&mut self, nonce_commitment: H256) -> Result<()> {
        if self.nonce_commitment.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Cannot add nonce commitment twice for same signer",
            ));
        }

        self.nonce_commitment = Some(nonce_commitment);
        Ok(())
    }

    /// Adds nonce to current signer if not already added.
    pub fn add_nonce(&mut self, nonce: PublicKey) -> Result<()> {
        if self.nonce.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Cannot add nonce twice for same signer",
            ));
        }

        self.nonce = Some(nonce);
        Ok(())
    }

    /// Adds partial signature to current signer if not already added.
    pub fn add_partial_signature(&mut self, partial_signature: H256) -> Result<()> {
        if self.partial_signature.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Cannot add partial signature twice for same signer",
            ));
        }

        self.partial_signature = Some(partial_signature);
        Ok(())
    }
}
