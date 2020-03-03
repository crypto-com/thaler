use std::convert::TryFrom;

use parity_scale_codec::{Decode, Encode};
use rand::rngs::OsRng;
use secp256k1::key::MuSigPreSession;
use secp256k1::musig::{
    MuSigNonce, MuSigNonceCommitment, MuSigPartialSignature, MuSigSession, MuSigSessionID,
};
use secp256k1::schnorrsig::SchnorrSignature;
use secp256k1::{key::XOnlyPublicKey, Message, SecretKey};

use chain_core::common::H256;
use client_common::{Error, ErrorKind, PrivateKey, PublicKey, Result, ResultExt, SECP};

use super::Signer;

/// A MultiSig session as a basic building block
#[derive(Debug, Encode, Decode)]
pub struct MultiSigSession {
    /// Session id
    pub id: H256,
    /// The message to be signed
    pub message: H256,
    /// Data of all the signers (also includes data of current signer). This is sorted by public key of signer.
    pub signers: Vec<Signer>,
    /// Public key of current signer
    pub public_key: PublicKey,
    /// Private key of current signer
    pub private_key: PrivateKey,
}

impl MultiSigSession {
    /// for some reason, the old implementation exposed all internals + kept reconstructing the session?
    /// this is a minimal change to get it working
    /// TODO: change all these client-* to something safe, but not so naive and super-inefficient way, as it was before
    /// (perhaps after MuSig API stabilizes more?)
    fn get_preinit(&self) -> Result<(XOnlyPublicKey, MuSigPreSession)> {
        let pks: Vec<PublicKey> = self
            .signers
            .iter()
            .map(|signer| signer.public_key.clone())
            .collect();
        PublicKey::combine(&pks)
    }

    /// Create a new instance of MultiSigSession
    pub fn new(
        message: H256,
        mut signer_public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        self_private_key: PrivateKey,
    ) -> Result<Self> {
        if PublicKey::from(&self_private_key) != self_public_key {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Invalid self public/private keypair",
            ));
        }

        if signer_public_keys.len() <= 1 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Cannot create a session with less than 2 signers",
            ));
        }

        signer_public_keys.sort();

        if signer_public_keys.binary_search(&self_public_key).is_err() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Self public key is not present in list of signers",
            ));
        }

        let signers = signer_public_keys
            .into_iter()
            .map(|public_key| Signer {
                public_key,
                nonce_commitment: None,
                nonce: None,
                partial_signature: None,
            })
            .collect::<Vec<Signer>>();

        let mut rng = OsRng;
        let session_id = H256::try_from(&MuSigSessionID::new(&mut rng)[..]).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize session ID from bytes",
            )
        })?;

        Ok(MultiSigSession {
            id: session_id,
            message,
            signers,
            public_key: self_public_key,
            private_key: self_private_key,
        })
    }

    /// Returns nonce commitment of current signer
    pub fn nonce_commitment(&self) -> Result<H256> {
        SECP.with(|secp| -> Result<H256> {
            let (pk, pre_init) = self.get_preinit()?;
            let session = MuSigSession::new(
                &secp,
                MuSigSessionID::from_slice(&self.id).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize multi-sig session ID from bytes",
                    )
                })?,
                &Message::from_slice(&self.message).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize message to sign from bytes",
                    )
                })?,
                &pk,
                &pre_init,
                self.signers.len(),
                self.signer_index(&self.public_key)?,
                &SecretKey::from(&self.private_key),
            )
            .chain(|| (ErrorKind::MultiSigError, "Unable to create session"))?;

            Ok(session.get_my_nonce_commitment().serialize())
        })
    }

    /// Adds nonce commitment for signer corresponding to given public key
    pub fn add_nonce_commitment(
        &mut self,
        public_key: &PublicKey,
        nonce_commitment: H256,
    ) -> Result<()> {
        let signer_index = self.signer_index(public_key)?;
        self.signers[signer_index].add_nonce_commitment(nonce_commitment)
    }

    /// Returns nonce of current signer. This function will fail if nonce commitments from all co-signers are not
    /// received.
    pub fn nonce(&self) -> Result<H256> {
        let nonce_commitments = self.nonce_commitments()?;

        SECP.with(|secp| -> Result<H256> {
            let (pk, pre_init) = self.get_preinit()?;
            let mut session = MuSigSession::new(
                &secp,
                MuSigSessionID::from_slice(&self.id).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize multi-sig session ID from bytes",
                    )
                })?,
                &Message::from_slice(&self.message).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize message to sign from bytes",
                    )
                })?,
                &pk,
                &pre_init,
                self.signers.len(),
                self.signer_index(&self.public_key)?,
                &SecretKey::from(&self.private_key),
            )
            .chain(|| (ErrorKind::MultiSigError, "Unable to create session"))?;

            nonce_commitments
                .into_iter()
                .map(|(public_key, nonce_commitment)| -> Result<()> {
                    session.set_nonce_commitment(
                        MuSigNonceCommitment::deserialize_from(nonce_commitment),
                        self.signer_index(&public_key)?,
                    );
                    Ok(())
                })
                .collect::<Result<Vec<()>>>()?;

            let public_nonce = session.get_public_nonce().chain(|| {
                (
                    ErrorKind::MultiSigError,
                    "Missing nonce commitment of at least one signer",
                )
            })?;

            Ok(public_nonce.serialize())
        })
    }

    /// Adds nonce for signer corresponding to given public key
    pub fn add_nonce(&mut self, public_key: &PublicKey, nonce: H256) -> Result<()> {
        let signer_index = self.signer_index(public_key)?;
        self.signers[signer_index].add_nonce(nonce)
    }

    /// Returns partial signature of current signer. This function will fail if nonces from all co-signers are not
    /// received.
    pub fn partial_signature(&self) -> Result<H256> {
        let nonce_commitments = self.nonce_commitments()?;
        let nonces = self.nonces()?;

        SECP.with(|secp| -> Result<H256> {
            let (pk, pre_init) = self.get_preinit()?;
            let mut session = MuSigSession::new(
                &secp,
                MuSigSessionID::from_slice(&self.id).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize multi-sig session ID from bytes",
                    )
                })?,
                &Message::from_slice(&self.message).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize message to sign from bytes",
                    )
                })?,
                &pk,
                &pre_init,
                self.signers.len(),
                self.signer_index(&self.public_key)?,
                &SecretKey::from(&self.private_key),
            )
            .chain(|| (ErrorKind::MultiSigError, "Unable to create session"))?;

            nonce_commitments
                .into_iter()
                .map(|(public_key, nonce_commitment)| -> Result<()> {
                    session.set_nonce_commitment(
                        MuSigNonceCommitment::deserialize_from(nonce_commitment),
                        self.signer_index(&public_key)?,
                    );
                    Ok(())
                })
                .collect::<Result<Vec<()>>>()?;

            session.get_public_nonce().chain(|| {
                (
                    ErrorKind::MultiSigError,
                    "Missing nonce commitment of at least one signer",
                )
            })?;

            nonces
                .into_iter()
                .map(|(public_key, nonce)| {
                    session
                        .set_nonce(
                            self.signer_index(&public_key)?,
                            MuSigNonce::deserialize_from(nonce),
                        )
                        .chain(|| {
                            (
                                ErrorKind::MultiSigError,
                                format!("Missing nonce of signer with public key: {}", public_key),
                            )
                        })
                })
                .collect::<Result<Vec<()>>>()?;

            session
                .combine_nonces()
                .chain(|| (ErrorKind::MultiSigError, "Unable to combine nonces"))?;

            Ok(session
                .partial_sign()
                .chain(|| {
                    (
                        ErrorKind::MultiSigError,
                        "Unable to generate partial signature",
                    )
                })?
                .serialize())
        })
    }

    /// Adds partial signature for signer corresponding to given public key
    pub fn add_partial_signature(
        &mut self,
        public_key: &PublicKey,
        partial_signature: H256,
    ) -> Result<()> {
        let signer_index = self.signer_index(public_key)?;
        self.signers[signer_index].add_partial_signature(partial_signature)
    }

    /// Returns combined signature. This function will fail if partial signatures from all co-signers are not received.
    pub fn signature(&self) -> Result<SchnorrSignature> {
        let nonce_commitments = self.nonce_commitments()?;
        let nonces = self.nonces()?;
        let partial_signatures = self.partial_signatures()?;

        SECP.with(|secp| -> Result<SchnorrSignature> {
            let (pk, pre_init) = self.get_preinit()?;
            let mut session = MuSigSession::new(
                &secp,
                MuSigSessionID::from_slice(&self.id).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize multi-sig session ID from bytes",
                    )
                })?,
                &Message::from_slice(&self.message).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize message to sign from bytes",
                    )
                })?,
                &pk,
                &pre_init,
                self.signers.len(),
                self.signer_index(&self.public_key)?,
                &SecretKey::from(&self.private_key),
            )
            .chain(|| (ErrorKind::MultiSigError, "Unable to create session"))?;

            nonce_commitments
                .into_iter()
                .map(|(public_key, nonce_commitment)| -> Result<()> {
                    session.set_nonce_commitment(
                        MuSigNonceCommitment::deserialize_from(nonce_commitment),
                        self.signer_index(&public_key)?,
                    );
                    Ok(())
                })
                .collect::<Result<Vec<()>>>()?;

            session.get_public_nonce().chain(|| {
                (
                    ErrorKind::MultiSigError,
                    "Missing nonce commitment of at least one signer",
                )
            })?;

            nonces
                .into_iter()
                .map(|(public_key, nonce)| {
                    session
                        .set_nonce(
                            self.signer_index(&public_key)?,
                            MuSigNonce::deserialize_from(nonce),
                        )
                        .chain(|| {
                            (
                                ErrorKind::MultiSigError,
                                format!("Missing nonce of signer with public key: {}", public_key),
                            )
                        })
                })
                .collect::<Result<Vec<()>>>()?;

            session
                .combine_nonces()
                .chain(|| (ErrorKind::MultiSigError, "Unable to combine nonces"))?;

            session.partial_sign().chain(|| {
                (
                    ErrorKind::MultiSigError,
                    "Unable to generate partial signature",
                )
            })?;

            Ok(session
                .partial_sig_combine(
                    &partial_signatures
                        .into_iter()
                        .map(|sig| {
                            MuSigPartialSignature::deserialize_from(sig).chain(|| {
                                (
                                    ErrorKind::DeserializationError,
                                    "Unable to deserialize partial signature from bytes",
                                )
                            })
                        })
                        .collect::<Result<Vec<MuSigPartialSignature>>>()?,
                )
                .chain(|| {
                    (
                        ErrorKind::MultiSigError,
                        "Unable to combine partial signatures",
                    )
                })?)
        })
    }

    /// Returns public keys of all signers in this session
    pub fn public_keys(&self) -> Vec<PublicKey> {
        self.signers
            .iter()
            .map(|signer| signer.public_key.clone())
            .collect()
    }

    /// Returns true if nonce commitment for given public key is already set, false otherwise
    pub fn has_nonce_commitment(&self, public_key: &PublicKey) -> Result<bool> {
        let signer_index = self.signer_index(public_key)?;
        Ok(self.signers[signer_index].nonce_commitment.is_some())
    }

    /// Returns true if nonce for given public key is already set, false otherwise
    pub fn has_nonce(&self, public_key: &PublicKey) -> Result<bool> {
        let signer_index = self.signer_index(public_key)?;
        Ok(self.signers[signer_index].nonce.is_some())
    }

    /// Returns true if partial signature for given public key is already set, false otherwise
    pub fn has_partial_signature(&mut self, public_key: &PublicKey) -> Result<bool> {
        let signer_index = self.signer_index(public_key)?;
        Ok(self.signers[signer_index].partial_signature.is_some())
    }

    /// Returns index of signer with given public key
    fn signer_index(&self, public_key: &PublicKey) -> Result<usize> {
        self.signers
            .binary_search_by(|signer| signer.public_key.cmp(&public_key))
            .map_err(|_| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Signer with public key ({}) not found", public_key),
                )
            })
    }

    /// Returns all the nonce commitments. This function will fail if nonce commitments from all co-signers are not
    /// received.
    fn nonce_commitments(&self) -> Result<Vec<(PublicKey, H256)>> {
        self.signers
            .iter()
            .map(|signer| match signer.nonce_commitment {
                None => Err(Error::new(
                    ErrorKind::MultiSigError,
                    format!(
                        "Missing nonce commitment for signer with public key: {}",
                        signer.public_key
                    ),
                )),
                Some(nonce_commitment) => Ok((signer.public_key.clone(), nonce_commitment)),
            })
            .collect()
    }

    /// Returns all the nonces. This function will fail if nonces from all co-signers are not received.
    fn nonces(&self) -> Result<Vec<(PublicKey, H256)>> {
        self.signers
            .iter()
            .map(|signer| match signer.nonce {
                None => Err(Error::new(
                    ErrorKind::MultiSigError,
                    format!(
                        "Missing nonce for signer with public key: {}",
                        signer.public_key
                    ),
                )),
                Some(ref nonce) => Ok((signer.public_key.clone(), *nonce)),
            })
            .collect()
    }

    /// Returns all the partial signatures. This function will fail if partial signatures from all co-signers are not
    /// received.
    fn partial_signatures(&self) -> Result<Vec<H256>> {
        self.signers
            .iter()
            .map(|signer| match signer.partial_signature {
                None => Err(Error::new(
                    ErrorKind::MultiSigError,
                    format!(
                        "Missing partial signature for signer with public key: {}",
                        signer.public_key
                    ),
                )),
                Some(partial_signature) => Ok(partial_signature),
            })
            .collect()
    }
}

#[cfg(test)]
mod multi_sig_session_tests {
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

        let mut session_1 = MultiSigSession::new(
            message,
            vec![public_key_1.clone(), public_key_2.clone()],
            public_key_1.clone(),
            private_key_1.clone(),
        )
        .unwrap();
        let mut session_2 = MultiSigSession::new(
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
            .add_nonce_commitment(&public_key_1, nonce_commitment_1)
            .expect("Should be able to add nonce commitment to session 1");
        session_1
            .add_nonce_commitment(&public_key_2, nonce_commitment_2)
            .expect("Should be able to add nonce commitment to session 1");
        session_2
            .add_nonce_commitment(&public_key_1, nonce_commitment_1)
            .expect("Should be able to add nonce commitment to session 2");
        session_2
            .add_nonce_commitment(&public_key_2, nonce_commitment_2)
            .expect("Should be able to add nonce commitment to session 2");

        let nonce_1 = session_1.nonce().unwrap();
        assert!(
            session_1.nonce().is_ok(),
            "Should be able to retrieve nonce multiple times"
        );

        let nonce_2 = session_2.nonce().unwrap();

        session_1
            .add_nonce(&public_key_1, nonce_1.clone())
            .expect("Should be able to add nonce to session 1");
        session_1
            .add_nonce(&public_key_2, nonce_2.clone())
            .expect("Should be able to add nonce to session 1");
        session_1
            .add_nonce(&public_key_2, nonce_1.clone())
            .expect_err("Should not be able to modify an already existing nonce");
        session_2
            .add_nonce(&public_key_1, nonce_1.clone())
            .expect("Should be able to add nonce to session 2");
        session_2
            .add_nonce(&public_key_2, nonce_2.clone())
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
            .add_partial_signature(&public_key_1, partial_signature_1)
            .expect("Should be able to add partial signature to session 1");
        session_1
            .add_partial_signature(&public_key_2, partial_signature_2)
            .expect("Should be able to add partial signature to session 1");
        session_2
            .add_partial_signature(&public_key_1, partial_signature_1)
            .expect("Should be able to add partial signature to session 2");
        session_2
            .add_partial_signature(&public_key_2, partial_signature_2)
            .expect("Should be able to add partial signature to session 2");

        let signature_1 = session_1.signature().unwrap();
        let signature_2 = session_2.signature().unwrap();

        assert_eq!(signature_1, signature_2);

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
