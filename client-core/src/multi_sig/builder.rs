use parity_scale_codec::{Decode, Encode};
use secp256k1::schnorrsig::SchnorrSignature;

use chain_core::common::H256;
use client_common::{ErrorKind, PrivateKey, PublicKey, Result, ResultExt};

use super::MultiSigSession;

/// MultiSig session builder tailored for Crypto.com chain flow
///
/// WARNING: Never restore MultiSig builder from an untrusted source or
/// from a source not created by you.
/// Restoring from such a source can result in complete lost of your funds.
/// If you are in doubt, always create a new session builder and restart
/// the whole process from scratch.
pub struct MultiSigBuilder {
    session: MultiSigSession,
}

impl MultiSigBuilder {
    /// Creates a new MultiSig builder
    ///
    /// # Arguments
    ///
    /// - `message`: Message to be signed,
    /// - `signer_public_keys`: Public keys of all the signers (including current signer)
    /// - `self_public_key`: Public key of current signer
    /// - `self_private_key`: Private key of current signer
    pub fn new(
        message: H256,
        signer_public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        self_private_key: PrivateKey,
    ) -> Result<Self> {
        let session = MultiSigSession::new(
            message,
            signer_public_keys,
            self_public_key,
            self_private_key,
        )?;

        Ok(MultiSigBuilder { session })
    }

    /// Returns the session Id
    pub fn id(&self) -> H256 {
        self.session.id
    }

    /// Returns nonce commitment of current signer. Add the nonce commitment to
    /// the session if the current signer has no nonce commitment added before.
    pub fn nonce_commitment(&mut self) -> Result<H256> {
        let nonce_commitment = self.session.nonce_commitment()?;

        let public_key = &self.session.public_key.clone();
        if !self.session.has_nonce_commitment(public_key)? {
            self.session
                .add_nonce_commitment(public_key, nonce_commitment.clone())?;
        }

        Ok(nonce_commitment)
    }

    /// Adds a nonce commitment from a public key.
    pub fn add_nonce_commitment(
        &mut self,
        public_key: &PublicKey,
        nonce_commitment: H256,
    ) -> Result<()> {
        self.session
            .add_nonce_commitment(&public_key, nonce_commitment)?;

        Ok(())
    }

    /// Returns nonce of current signer. Add the nonce to the session if the
    /// current signer has no nonce added before.
    ///
    /// This function will fail if nonce commitments from all co-signers are
    /// not received.
    pub fn nonce(&mut self) -> Result<H256> {
        let nonce = self.session.nonce()?;

        let public_key = &self.session.public_key.clone();
        if !self.session.has_nonce(public_key)? {
            self.session.add_nonce(public_key, nonce.clone())?;
        }

        Ok(nonce)
    }

    /// Adds a nonce from a public key to session.
    pub fn add_nonce(&mut self, public_key: &PublicKey, nonce: &H256) -> Result<()> {
        self.session.add_nonce(public_key, nonce.clone())?;

        Ok(())
    }

    /// Returns partial signature of current signer. Add the partial signature
    /// to the session if the current signer has no partial signature added
    /// before.
    ///
    /// This function will fail if nonces from all co-signers are not received.
    pub fn partial_signature(&mut self) -> Result<H256> {
        let partial_signature = self.session.partial_signature()?;
        let public_key = &self.session.public_key.clone();

        if !self.session.has_partial_signature(public_key)? {
            self.session
                .add_partial_signature(public_key, partial_signature)?;
        }

        Ok(partial_signature)
    }

    /// Adds a partial signature from a public key to session
    pub fn add_partial_signature(
        &mut self,
        public_key: &PublicKey,
        partial_signature: H256,
    ) -> Result<()> {
        self.session
            .add_partial_signature(public_key, partial_signature)?;

        Ok(())
    }

    /// Returns final signature.
    ///
    /// This function will fail if partial signatures from all co-signers are not received.
    pub fn signature(&self) -> Result<SchnorrSignature> {
        self.session.signature()
    }

    /// Returns public keys of all signers in this session
    pub fn public_keys(&self) -> Vec<PublicKey> {
        self.session.public_keys()
    }

    /// Returns true if nonce commitment for given public key is already set,
    /// false otherwise.
    pub fn has_nonce_commitment(&self, public_key: &PublicKey) -> Result<bool> {
        self.session.has_nonce_commitment(public_key)
    }

    /// Returns true if nonce for given public key is already set, false
    /// otherwise.
    pub fn has_nonce(&self, public_key: &PublicKey) -> Result<bool> {
        self.session.has_nonce(public_key)
    }

    /// Returns true if partial signature for given public key is already set,
    /// false otherwise.
    pub fn has_partial_signature(&mut self, public_key: &PublicKey) -> Result<bool> {
        self.session.has_partial_signature(public_key)
    }

    /// Returns incompleted MultiSig session in bytes
    pub fn to_incomplete(&self) -> Vec<u8> {
        self.session.encode()
    }

    /// Restore MultiSig session builder from encoded incompleted bytes
    ///
    /// WARNING: Never restore MultiSig builder from an untrusted source or
    /// from a source not created by you.
    /// Restoring from such a source can result in complete lost of your funds.
    /// If you are in doubt, always create a new session builder and restart
    /// the whole process from scratch.
    pub fn from_incomplete_insecure(bytes: Vec<u8>) -> Result<Self> {
        let session = MultiSigSession::decode(&mut bytes.as_slice()).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize MultiSig session",
            )
        })?;

        Ok(MultiSigBuilder { session })
    }
}

#[cfg(test)]
mod multi_sig_builder_tests {
    use super::*;

    use secp256k1::schnorrsig::schnorr_verify;
    use secp256k1::Message;

    use client_common::SECP;

    #[test]
    fn check_multi_sig_transaction_flow() {
        let message = [1u8; 32];

        let private_key_1 = PrivateKey::new().unwrap();
        let private_key_2 = PrivateKey::new().unwrap();

        let public_key_1 = PublicKey::from(&private_key_1);
        let public_key_2 = PublicKey::from(&private_key_2);

        let mut session_1 = MultiSigBuilder::new(
            message,
            vec![public_key_1.clone(), public_key_2.clone()],
            public_key_1.clone(),
            private_key_1.clone(),
        )
        .unwrap();
        let mut session_2 = MultiSigBuilder::new(
            message,
            vec![public_key_1.clone(), public_key_2.clone()],
            public_key_2.clone(),
            private_key_2.clone(),
        )
        .unwrap();

        let nonce_commitment_1 = session_1.nonce_commitment().unwrap();
        assert!(
            session_1.nonce_commitment().is_ok(),
            "Should be able to retrieve nonce commitment multiple times"
        );

        let nonce_commitment_2 = session_2.nonce_commitment().unwrap();

        session_1
            .add_nonce_commitment(&public_key_2, nonce_commitment_2)
            .expect("Should be able to add nonce commitment to session 1");
        session_2
            .add_nonce_commitment(&public_key_1, nonce_commitment_1)
            .expect("Should be able to add nonce commitment to session 2");

        let nonce_1 = session_1.nonce().unwrap();
        assert!(
            session_1.nonce().is_ok(),
            "Should be able to retrieve nonce multiple times"
        );

        let nonce_2 = session_2.nonce().unwrap();

        session_1
            .add_nonce(&public_key_2, &nonce_2)
            .expect("Should be able to add nonce to session 1");
        session_1
            .add_nonce(&public_key_2, &nonce_1)
            .expect_err("Should not be able to modify an already existing nonce");
        session_2
            .add_nonce(&public_key_1, &nonce_1)
            .expect("Should be able to add nonce to session 2");

        let partial_signature_1 = session_1
            .partial_signature()
            .expect("Should be able to generate partial signature for session 1");
        assert!(
            session_1.partial_signature().is_ok(),
            "Should be able to retrieve partial signatures multiple times"
        );

        let partial_signature_2 = session_2
            .partial_signature()
            .expect("Should be able to generate partial signature for session 2");

        session_1
            .add_partial_signature(&public_key_2, partial_signature_2)
            .expect("Should be able to add partial signature to session 1");
        session_2
            .add_partial_signature(&public_key_1, partial_signature_1)
            .expect("Should be able to add partial signature to session 2");

        let encoded = session_1.to_incomplete();

        let restored_session_1 = MultiSigBuilder::from_incomplete_insecure(encoded)
            .expect("Should be able to restore from encoded incompleted bytes");

        let signature_1 = session_1.signature().unwrap();
        let restored_signature_1 = restored_session_1
            .signature()
            .expect("Should be able to get signatured from restored session");
        let signature_2 = session_2.signature().unwrap();

        assert_eq!(signature_1, signature_2);
        assert_eq!(restored_signature_1, signature_2);

        let mut public_keys = vec![public_key_1, public_key_2];
        public_keys.sort();

        let combined_public_key = PublicKey::combine(&public_keys).unwrap().0;
        let message = Message::from_slice(&message).unwrap();

        SECP.with(|secp| {
            schnorr_verify(&secp, &message, &signature_1, &combined_public_key.into())
                .expect("Invalid signature");
        })
    }
}
