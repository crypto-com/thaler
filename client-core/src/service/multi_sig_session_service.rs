use std::convert::TryFrom;

use failure::ResultExt;
use parity_codec::{Decode, Encode};
use rand::rngs::OsRng;
use secp256k1::key::PublicKeyHash;
use secp256k1::musig::{MuSigNonceCommitment, MuSigPartialSignature, MuSigSession, MuSigSessionID};
use secp256k1::schnorrsig::SchnorrSignature;
use secp256k1::{Message, PublicKey as SecpPublicKey, SecretKey};
use secstr::SecUtf8;

use chain_core::common::H256;
use client_common::{Error, ErrorKind, Result, SecureStorage, Storage};

use crate::{PrivateKey, PublicKey, SECP};

const KEYSPACE: &str = "core_multi_sig_address";

/// A multi-sig session
#[derive(Debug, Encode, Decode)]
struct MultiSigSession {
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
    /// Combined public key
    pub combined_public_key: PublicKey,
    /// Combined public key hash
    pub combined_public_key_hash: H256,
}

impl MultiSigSession {
    /// Adds nonce commitment for signer corresponding to given public key
    pub fn add_nonce_commitment(
        &mut self,
        public_key: &PublicKey,
        nonce_commitment: H256,
    ) -> Result<()> {
        let signer_index = self.signer_index(public_key)?;
        self.signers[signer_index].add_nonce_commitment(nonce_commitment)
    }

    /// Adds nonce for signer corresponding to given public key
    pub fn add_nonce(&mut self, public_key: &PublicKey, nonce: PublicKey) -> Result<()> {
        let signer_index = self.signer_index(public_key)?;
        self.signers[signer_index].add_nonce(nonce)
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

    /// Returns nonce commitment of current signer
    pub fn nonce_commitment(&self) -> Result<H256> {
        SECP.with(|secp| -> Result<H256> {
            let session = MuSigSession::new(
                &secp,
                MuSigSessionID::from_slice(&self.id).context(ErrorKind::DeserializationError)?,
                &Message::from_slice(&self.message).context(ErrorKind::DeserializationError)?,
                &SecpPublicKey::from(&self.combined_public_key),
                &PublicKeyHash::deserialize_from(self.combined_public_key_hash),
                self.signers.len(),
                self.signer_index(&self.public_key)?,
                &SecretKey::from(&self.private_key),
            )
            .context(ErrorKind::SessionCreationError)?;

            Ok(session.get_my_nonce_commitment().serialize())
        })
    }

    /// Returns nonce of current signer. This function will fail if nonce commitments from all co-signers are not
    /// received.
    pub fn nonce(&self) -> Result<PublicKey> {
        let nonce_commitments = self.nonce_commitments()?;

        SECP.with(|secp| -> Result<PublicKey> {
            let mut session = MuSigSession::new(
                &secp,
                MuSigSessionID::from_slice(&self.id).context(ErrorKind::DeserializationError)?,
                &Message::from_slice(&self.message).context(ErrorKind::DeserializationError)?,
                &SecpPublicKey::from(&self.combined_public_key),
                &PublicKeyHash::deserialize_from(self.combined_public_key_hash),
                self.signers.len(),
                self.signer_index(&self.public_key)?,
                &SecretKey::from(&self.private_key),
            )
            .context(ErrorKind::SessionCreationError)?;

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

            let public_nonce = session
                .get_public_nonce()
                .context(ErrorKind::MissingNonceCommitment)?;

            Ok(public_nonce.into())
        })
    }

    /// Returns partial signature of current signer. This function will fail if nonces from all co-signers are not
    /// received.
    pub fn partial_signature(&self) -> Result<H256> {
        let nonce_commitments = self.nonce_commitments()?;
        let nonces = self.nonces()?;

        SECP.with(|secp| -> Result<H256> {
            let mut session = MuSigSession::new(
                &secp,
                MuSigSessionID::from_slice(&self.id).context(ErrorKind::DeserializationError)?,
                &Message::from_slice(&self.message).context(ErrorKind::DeserializationError)?,
                &SecpPublicKey::from(&self.combined_public_key),
                &PublicKeyHash::deserialize_from(self.combined_public_key_hash),
                self.signers.len(),
                self.signer_index(&self.public_key)?,
                &SecretKey::from(&self.private_key),
            )
            .context(ErrorKind::SessionCreationError)?;

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

            session
                .get_public_nonce()
                .context(ErrorKind::MissingNonceCommitment)?;

            nonces
                .into_iter()
                .map(|(public_key, nonce)| {
                    Ok(session
                        .set_nonce(self.signer_index(&public_key)?, nonce.into())
                        .context(ErrorKind::MissingNonce)?)
                })
                .collect::<Result<Vec<()>>>()?;

            session
                .combine_nonces()
                .context(ErrorKind::NonceCombiningError)?;

            Ok(session
                .partial_sign()
                .context(ErrorKind::PartialSignError)?
                .serialize())
        })
    }

    /// Returns combined signature. This function will fail if partial signatures from all co-signers are not received.
    pub fn signature(&self) -> Result<SchnorrSignature> {
        let nonce_commitments = self.nonce_commitments()?;
        let nonces = self.nonces()?;
        let partial_signatures = self.partial_signatures()?;

        SECP.with(|secp| -> Result<SchnorrSignature> {
            let mut session = MuSigSession::new(
                &secp,
                MuSigSessionID::from_slice(&self.id).context(ErrorKind::DeserializationError)?,
                &Message::from_slice(&self.message).context(ErrorKind::DeserializationError)?,
                &SecpPublicKey::from(&self.combined_public_key),
                &PublicKeyHash::deserialize_from(self.combined_public_key_hash),
                self.signers.len(),
                self.signer_index(&self.public_key)?,
                &SecretKey::from(&self.private_key),
            )
            .context(ErrorKind::SessionCreationError)?;

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

            session
                .get_public_nonce()
                .context(ErrorKind::MissingNonceCommitment)?;

            nonces
                .into_iter()
                .map(|(public_key, nonce)| {
                    Ok(session
                        .set_nonce(self.signer_index(&public_key)?, nonce.into())
                        .context(ErrorKind::MissingNonce)?)
                })
                .collect::<Result<Vec<()>>>()?;

            session
                .combine_nonces()
                .context(ErrorKind::NonceCombiningError)?;

            session
                .partial_sign()
                .context(ErrorKind::PartialSignError)?;

            Ok(session
                .partial_sig_combine(
                    &partial_signatures
                        .into_iter()
                        .map(|sig| {
                            Ok(MuSigPartialSignature::deserialize_from(sig)
                                .context(ErrorKind::DeserializationError)?)
                        })
                        .collect::<Result<Vec<MuSigPartialSignature>>>()?,
                )
                .context(ErrorKind::SigningError)?)
        })
    }

    /// Returns all the partial signatures. This function will fail if partial signatures from all co-signers are not
    /// received.
    fn partial_signatures(&self) -> Result<Vec<H256>> {
        self.signers
            .iter()
            .map(|signer| match signer.partial_signature {
                None => Err(ErrorKind::MissingPartialSignature.into()),
                Some(partial_signature) => Ok(partial_signature),
            })
            .collect()
    }

    /// Returns all the nonces. This function will fail if nonces from all co-signers are not received.
    fn nonces(&self) -> Result<Vec<(PublicKey, PublicKey)>> {
        self.signers
            .iter()
            .map(|signer| match signer.nonce {
                None => Err(ErrorKind::MissingNonce.into()),
                Some(ref nonce) => Ok((signer.public_key.clone(), nonce.clone())),
            })
            .collect()
    }

    /// Returns all the nonce commitments. This function will fail if nonce commitments from all co-signers are not
    /// received.
    fn nonce_commitments(&self) -> Result<Vec<(PublicKey, H256)>> {
        self.signers
            .iter()
            .map(|signer| match signer.nonce_commitment {
                None => Err(ErrorKind::MissingNonceCommitment.into()),
                Some(nonce_commitment) => Ok((signer.public_key.clone(), nonce_commitment)),
            })
            .collect()
    }

    /// Returns index of signer with given public key
    fn signer_index(&self, public_key: &PublicKey) -> Result<usize> {
        self.signers
            .binary_search_by(|signer| signer.public_key.cmp(&public_key))
            .map_err(|_| Error::from(ErrorKind::SignerNotFound))
    }
}

#[derive(Debug, Encode, Decode)]
struct Signer {
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
            return Err(Error::from(ErrorKind::InvalidInput));
        }

        self.nonce_commitment = Some(nonce_commitment);
        Ok(())
    }

    /// Adds nonce to current signer if not already added.
    pub fn add_nonce(&mut self, nonce: PublicKey) -> Result<()> {
        if self.nonce.is_some() {
            return Err(Error::from(ErrorKind::InvalidInput));
        }

        self.nonce = Some(nonce);
        Ok(())
    }

    /// Adds partial signature to current signer if not already added.
    pub fn add_partial_signature(&mut self, partial_signature: H256) -> Result<()> {
        if self.partial_signature.is_some() {
            return Err(Error::from(ErrorKind::InvalidInput));
        }

        self.partial_signature = Some(partial_signature);
        Ok(())
    }
}

/// Maintains mapping `multi-sig session-id -> multi-sig session`
#[derive(Debug, Default, Clone)]
pub struct MultiSigSessionService<T: Storage> {
    storage: T,
}

impl<T> MultiSigSessionService<T>
where
    T: Storage,
{
    /// Creates a new instance of multi-sig session service
    pub fn new(storage: T) -> Self {
        Self { storage }
    }

    /// Creates a new session and returns session-id
    ///
    /// # Arguments
    ///
    /// - `message`: Message to be signed,
    /// - `signer_public_keys`: Public keys of all the signers (including current signer)
    /// - `self_public_key`: Public key of current signer
    /// - `self_private_key`: Private key of current signer
    /// - `passphrase`: Passphrase for encryption
    pub fn new_session(
        &self,
        message: H256,
        mut signer_public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        self_private_key: PrivateKey,
        passphrase: &SecUtf8,
    ) -> Result<H256> {
        if PublicKey::from(&self_private_key) != self_public_key || signer_public_keys.len() <= 1 {
            return Err(ErrorKind::InvalidInput.into());
        }

        signer_public_keys.sort();

        if signer_public_keys.binary_search(&self_public_key).is_err() {
            return Err(ErrorKind::InvalidInput.into());
        }

        let (combined_public_key, combined_public_key_hash) =
            PublicKey::combine(&signer_public_keys)?;

        let signers = signer_public_keys
            .into_iter()
            .map(|public_key| Signer {
                public_key,
                nonce_commitment: None,
                nonce: None,
                partial_signature: None,
            })
            .collect::<Vec<Signer>>();

        let mut rng = OsRng::new().context(ErrorKind::KeyGenerationError)?;
        let session_id = H256::try_from(&MuSigSessionID::new(&mut rng)[..])
            .context(ErrorKind::DeserializationError)?;

        let session = MultiSigSession {
            id: session_id,
            message,
            signers,
            public_key: self_public_key,
            private_key: self_private_key,
            combined_public_key,
            combined_public_key_hash,
        };

        self.set_session(&session_id, session, passphrase)?;

        Ok(session_id)
    }

    /// Returns nonce commitment of self
    pub fn nonce_commitment(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<H256> {
        let mut session = self.get_session(session_id, passphrase)?;
        let nonce_commitment = session.nonce_commitment()?;
        let public_key = session.public_key.clone();
        session.add_nonce_commitment(&public_key, nonce_commitment)?;
        self.set_session(session_id, session, passphrase)?;

        Ok(nonce_commitment)
    }

    /// Adds a nonce commitment from a public key to session with given id
    pub fn add_nonce_commitment(
        &self,
        session_id: &H256,
        nonce_commitment: H256,
        public_key: &PublicKey,
        passphrase: &SecUtf8,
    ) -> Result<()> {
        // TODO: Implement compare and swap?
        let mut session = self.get_session(session_id, passphrase)?;
        session.add_nonce_commitment(public_key, nonce_commitment)?;
        self.set_session(session_id, session, passphrase)
    }

    /// Returns nonce of self. This function will fail if nonce commitments from all co-signers are not received.
    pub fn nonce(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<PublicKey> {
        let mut session = self.get_session(session_id, passphrase)?;
        let nonce = session.nonce()?;
        let public_key = session.public_key.clone();
        session.add_nonce(&public_key, nonce.clone())?;
        self.set_session(session_id, session, passphrase)?;
        Ok(nonce)
    }

    /// Adds a nonce from a public key to session with given id
    pub fn add_nonce(
        &self,
        session_id: &H256,
        nonce: PublicKey,
        public_key: &PublicKey,
        passphrase: &SecUtf8,
    ) -> Result<()> {
        // TODO: Implement compare and swap?
        let mut session = self.get_session(session_id, passphrase)?;
        session.add_nonce(public_key, nonce)?;
        self.set_session(session_id, session, passphrase)
    }

    /// Returns partial signature of self. This function will fail if nonces from all co-signers are not received.
    pub fn partial_signature(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<H256> {
        let mut session = self.get_session(session_id, passphrase)?;
        let partial_signature = session.partial_signature()?;
        let public_key = session.public_key.clone();
        session.add_partial_signature(&public_key, partial_signature)?;
        self.set_session(session_id, session, passphrase)?;
        Ok(partial_signature)
    }

    /// Adds a partial signature from a public key to session with given id
    pub fn add_partial_signature(
        &self,
        session_id: &H256,
        partial_signature: H256,
        public_key: &PublicKey,
        passphrase: &SecUtf8,
    ) -> Result<()> {
        // TODO: Implement compare and swap?
        let mut session = self.get_session(session_id, passphrase)?;
        session.add_partial_signature(public_key, partial_signature)?;
        self.set_session(session_id, session, passphrase)
    }

    /// Returns final signature. This function will fail if partial signatures from all co-signers are not received.
    pub fn signature(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<SchnorrSignature> {
        let session = self.get_session(session_id, passphrase)?;
        session.signature()
    }

    /// Retrieves a session from storage
    fn get_session(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<MultiSigSession> {
        let session_bytes = self
            .storage
            .get_secure(KEYSPACE, session_id, passphrase)?
            .ok_or_else(|| Error::from(ErrorKind::SessionNotFound))?;
        MultiSigSession::decode(&mut session_bytes.as_slice())
            .ok_or_else(|| Error::from(ErrorKind::DeserializationError))
    }

    /// Persists a session in storage
    fn set_session(
        &self,
        session_id: &H256,
        session: MultiSigSession,
        passphrase: &SecUtf8,
    ) -> Result<()> {
        self.storage
            .set_secure(KEYSPACE, session_id, session.encode(), passphrase)
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use secp256k1::schnorrsig::schnorr_verify;

    use client_common::storage::MemoryStorage;

    #[test]
    fn check_multi_sig_transaction_flow() {
        let multi_sig_service = MultiSigSessionService::new(MemoryStorage::default());
        let passphrase = SecUtf8::from("passphrase");

        let message = [1u8; 32];

        let private_key_1 = PrivateKey::new().unwrap();
        let private_key_2 = PrivateKey::new().unwrap();

        let public_key_1 = PublicKey::from(&private_key_1);
        let public_key_2 = PublicKey::from(&private_key_2);

        let session_id_1 = multi_sig_service
            .new_session(
                message,
                vec![public_key_1.clone(), public_key_2.clone()],
                public_key_1.clone(),
                private_key_1.clone(),
                &passphrase,
            )
            .unwrap();
        let session_id_2 = multi_sig_service
            .new_session(
                message,
                vec![public_key_1.clone(), public_key_2.clone()],
                public_key_2.clone(),
                private_key_2.clone(),
                &passphrase,
            )
            .unwrap();

        let nonce_commitment_1 = multi_sig_service
            .nonce_commitment(&session_id_1, &passphrase)
            .unwrap();
        let nonce_commitment_2 = multi_sig_service
            .nonce_commitment(&session_id_2, &passphrase)
            .unwrap();

        multi_sig_service
            .add_nonce_commitment(
                &session_id_1,
                nonce_commitment_2,
                &public_key_2,
                &passphrase,
            )
            .expect("Unable to add nonce commitment to session 1");
        multi_sig_service
            .add_nonce_commitment(
                &session_id_2,
                nonce_commitment_1,
                &public_key_1,
                &passphrase,
            )
            .expect("Unable to add nonce commitment to session 2");

        let nonce_1 = multi_sig_service.nonce(&session_id_1, &passphrase).unwrap();
        let nonce_2 = multi_sig_service.nonce(&session_id_2, &passphrase).unwrap();

        multi_sig_service
            .add_nonce(&session_id_1, nonce_2, &public_key_2, &passphrase)
            .expect("Unable to add nonce to session 1");
        multi_sig_service
            .add_nonce(&session_id_1, nonce_1.clone(), &public_key_2, &passphrase)
            .expect_err("Can modify an already existing nonce");
        multi_sig_service
            .add_nonce(&session_id_2, nonce_1, &public_key_1, &passphrase)
            .expect("Unable to add nonce to session 2");

        let partial_signature_1 = multi_sig_service
            .partial_signature(&session_id_1, &passphrase)
            .expect("Unable to generate partial signature for session 1");
        let partial_signature_2 = multi_sig_service
            .partial_signature(&session_id_2, &passphrase)
            .expect("Unable to generate partial signature for session 2");

        multi_sig_service
            .add_partial_signature(
                &session_id_1,
                partial_signature_2,
                &public_key_2,
                &passphrase,
            )
            .expect("Unable to add partial signature to session 1");
        multi_sig_service
            .add_partial_signature(
                &session_id_2,
                partial_signature_1,
                &public_key_1,
                &passphrase,
            )
            .expect("Unable to add partial signature to session 2");

        let signature_1 = multi_sig_service
            .signature(&session_id_1, &passphrase)
            .unwrap();
        let signature_2 = multi_sig_service
            .signature(&session_id_2, &passphrase)
            .unwrap();

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
