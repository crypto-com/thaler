use std::convert::TryFrom;

use parity_scale_codec::{Decode, Encode};
use rand::rngs::OsRng;
use secp256k1::key::PublicKeyHash;
use secp256k1::musig::{MuSigNonceCommitment, MuSigPartialSignature, MuSigSession, MuSigSessionID};
use secp256k1::schnorrsig::SchnorrSignature;
use secp256k1::{Message, PublicKey as SecpPublicKey, SecretKey};

use chain_core::common::H256;
use client_common::{
    Error, ErrorKind, PrivateKey, PublicKey, Result, ResultExt, SecKey, SecureStorage, Storage,
    SECP,
};

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
                &SecpPublicKey::from(&self.combined_public_key),
                &PublicKeyHash::deserialize_from(self.combined_public_key_hash),
                self.signers.len(),
                self.signer_index(&self.public_key)?,
                &SecretKey::from(&self.private_key),
            )
            .chain(|| (ErrorKind::MultiSigError, "Unable to create session"))?;

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
                &SecpPublicKey::from(&self.combined_public_key),
                &PublicKeyHash::deserialize_from(self.combined_public_key_hash),
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
                &SecpPublicKey::from(&self.combined_public_key),
                &PublicKeyHash::deserialize_from(self.combined_public_key_hash),
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
                        .set_nonce(self.signer_index(&public_key)?, nonce.into())
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

    /// Returns combined signature. This function will fail if partial signatures from all co-signers are not received.
    pub fn signature(&self) -> Result<SchnorrSignature> {
        let nonce_commitments = self.nonce_commitments()?;
        let nonces = self.nonces()?;
        let partial_signatures = self.partial_signatures()?;

        SECP.with(|secp| -> Result<SchnorrSignature> {
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
                &SecpPublicKey::from(&self.combined_public_key),
                &PublicKeyHash::deserialize_from(self.combined_public_key_hash),
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
                        .set_nonce(self.signer_index(&public_key)?, nonce.into())
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

    /// Returns all the nonces. This function will fail if nonces from all co-signers are not received.
    fn nonces(&self) -> Result<Vec<(PublicKey, PublicKey)>> {
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

    /// Returns true if nonce commitment for given public key is already set, false otherwise
    fn has_nonce_commitment(&self, public_key: &PublicKey) -> Result<bool> {
        let signer_index = self.signer_index(public_key)?;
        Ok(self.signers[signer_index].nonce_commitment.is_some())
    }

    /// Returns true if nonce for given public key is already set, false otherwise
    fn has_nonce(&self, public_key: &PublicKey) -> Result<bool> {
        let signer_index = self.signer_index(public_key)?;
        Ok(self.signers[signer_index].nonce.is_some())
    }

    /// Returns true if partial signature for given public key is already set, false otherwise
    fn has_partial_signature(&mut self, public_key: &PublicKey) -> Result<bool> {
        let signer_index = self.signer_index(public_key)?;
        Ok(self.signers[signer_index].partial_signature.is_some())
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
    /// - `enckey`: Passphrase for encryption
    pub fn new_session(
        &self,
        message: H256,
        mut signer_public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        self_private_key: PrivateKey,
        enckey: &SecKey,
    ) -> Result<H256> {
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

        let mut rng = OsRng;
        let session_id = H256::try_from(&MuSigSessionID::new(&mut rng)[..]).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize session ID from bytes",
            )
        })?;

        let session = MultiSigSession {
            id: session_id,
            message,
            signers,
            public_key: self_public_key,
            private_key: self_private_key,
            combined_public_key,
            combined_public_key_hash,
        };

        self.set_session(&session_id, session, enckey)?;

        Ok(session_id)
    }

    /// Returns nonce commitment of self
    pub fn nonce_commitment(&self, session_id: &H256, enckey: &SecKey) -> Result<H256> {
        let mut session = self.get_session(session_id, enckey)?;
        let nonce_commitment = session.nonce_commitment()?;
        let public_key = session.public_key.clone();

        if !session.has_nonce_commitment(&public_key)? {
            session.add_nonce_commitment(&public_key, nonce_commitment)?;
        }

        self.set_session(session_id, session, enckey)?;

        Ok(nonce_commitment)
    }

    /// Adds a nonce commitment from a public key to session with given id
    pub fn add_nonce_commitment(
        &self,
        session_id: &H256,
        nonce_commitment: H256,
        public_key: &PublicKey,
        enckey: &SecKey,
    ) -> Result<()> {
        self.storage
            .fetch_and_update_secure(KEYSPACE, session_id, enckey, |value| {
                let mut session_bytes = value.chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        format!("Session with ID ({}) not found", hex::encode(session_id)),
                    )
                })?;
                let mut session = MultiSigSession::decode(&mut session_bytes).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize multi-sig session from bytes",
                    )
                })?;
                session.add_nonce_commitment(public_key, nonce_commitment)?;

                Ok(Some(session.encode()))
            })
            .map(|_| ())
    }

    /// Returns nonce of self. This function will fail if nonce commitments from all co-signers are not received.
    pub fn nonce(&self, session_id: &H256, enckey: &SecKey) -> Result<PublicKey> {
        let mut session = self.get_session(session_id, enckey)?;
        let nonce = session.nonce()?;
        let public_key = session.public_key.clone();

        if !session.has_nonce(&public_key)? {
            session.add_nonce(&public_key, nonce.clone())?;
        }

        self.set_session(session_id, session, enckey)?;
        Ok(nonce)
    }

    /// Adds a nonce from a public key to session with given id
    pub fn add_nonce(
        &self,
        session_id: &H256,
        nonce: &PublicKey,
        public_key: &PublicKey,
        enckey: &SecKey,
    ) -> Result<()> {
        self.storage
            .fetch_and_update_secure(KEYSPACE, session_id, enckey, |value| {
                let mut session_bytes = value.chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        format!("Session with ID ({}) not found", hex::encode(session_id)),
                    )
                })?;
                let mut session = MultiSigSession::decode(&mut session_bytes).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize multi-sig session from bytes",
                    )
                })?;
                session.add_nonce(public_key, nonce.clone())?;

                Ok(Some(session.encode()))
            })
            .map(|_| ())
    }

    /// Returns partial signature of self. This function will fail if nonces from all co-signers are not received.
    pub fn partial_signature(&self, session_id: &H256, enckey: &SecKey) -> Result<H256> {
        let mut session = self.get_session(session_id, enckey)?;
        let partial_signature = session.partial_signature()?;
        let public_key = session.public_key.clone();

        if !session.has_partial_signature(&public_key)? {
            session.add_partial_signature(&public_key, partial_signature)?;
        }

        self.set_session(session_id, session, enckey)?;
        Ok(partial_signature)
    }

    /// Adds a partial signature from a public key to session with given id
    pub fn add_partial_signature(
        &self,
        session_id: &H256,
        partial_signature: H256,
        public_key: &PublicKey,
        enckey: &SecKey,
    ) -> Result<()> {
        self.storage
            .fetch_and_update_secure(KEYSPACE, session_id, enckey, |value| {
                let mut session_bytes = value.chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        format!("Session with ID ({}) not found", hex::encode(session_id)),
                    )
                })?;
                let mut session = MultiSigSession::decode(&mut session_bytes).chain(|| {
                    (
                        ErrorKind::DeserializationError,
                        "Unable to deserialize multi-sig session from bytes",
                    )
                })?;
                session.add_partial_signature(public_key, partial_signature)?;

                Ok(Some(session.encode()))
            })
            .map(|_| ())
    }

    /// Returns final signature. This function will fail if partial signatures from all co-signers are not received.
    pub fn signature(&self, session_id: &H256, enckey: &SecKey) -> Result<SchnorrSignature> {
        let session = self.get_session(session_id, enckey)?;
        session.signature()
    }

    /// Returns public keys of all signers in this session
    pub fn public_keys(&self, session_id: &H256, enckey: &SecKey) -> Result<Vec<PublicKey>> {
        let session = self.get_session(session_id, enckey)?;
        Ok(session.public_keys())
    }

    /// Retrieves a session from storage
    fn get_session(&self, session_id: &H256, enckey: &SecKey) -> Result<MultiSigSession> {
        let session_bytes = self
            .storage
            .get_secure(KEYSPACE, session_id, enckey)?
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    format!("Session with ID ({}) not found", hex::encode(session_id)),
                )
            })?;
        MultiSigSession::decode(&mut session_bytes.as_slice()).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to deserialize multi-sig session from bytes",
            )
        })
    }

    /// Persists a session in storage
    fn set_session(
        &self,
        session_id: &H256,
        session: MultiSigSession,
        enckey: &SecKey,
    ) -> Result<()> {
        self.storage
            .set_secure(KEYSPACE, session_id, session.encode(), enckey)
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secstr::SecUtf8;

    use secp256k1::schnorrsig::schnorr_verify;

    use client_common::{seckey::derive_enckey, storage::MemoryStorage};

    #[test]
    fn check_multi_sig_transaction_flow() {
        let multi_sig_service = MultiSigSessionService::new(MemoryStorage::default());
        let enckey = derive_enckey(&SecUtf8::from("passphrase"), "").unwrap();

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
                &enckey,
            )
            .unwrap();
        let session_id_2 = multi_sig_service
            .new_session(
                message,
                vec![public_key_1.clone(), public_key_2.clone()],
                public_key_2.clone(),
                private_key_2.clone(),
                &enckey,
            )
            .unwrap();

        let nonce_commitment_1 = multi_sig_service
            .nonce_commitment(&session_id_1, &enckey)
            .unwrap();
        assert!(
            multi_sig_service
                .nonce_commitment(&session_id_1, &enckey)
                .is_ok(),
            "Not able to retrieve nonce commitment multiple times"
        );

        let nonce_commitment_2 = multi_sig_service
            .nonce_commitment(&session_id_2, &enckey)
            .unwrap();

        multi_sig_service
            .add_nonce_commitment(&session_id_1, nonce_commitment_2, &public_key_2, &enckey)
            .expect("Unable to add nonce commitment to session 1");
        multi_sig_service
            .add_nonce_commitment(&session_id_2, nonce_commitment_1, &public_key_1, &enckey)
            .expect("Unable to add nonce commitment to session 2");

        let nonce_1 = multi_sig_service.nonce(&session_id_1, &enckey).unwrap();
        assert!(
            multi_sig_service.nonce(&session_id_1, &enckey).is_ok(),
            "Not able to retrieve nonce multiple times"
        );

        let nonce_2 = multi_sig_service.nonce(&session_id_2, &enckey).unwrap();

        multi_sig_service
            .add_nonce(&session_id_1, &nonce_2, &public_key_2, &enckey)
            .expect("Unable to add nonce to session 1");
        multi_sig_service
            .add_nonce(&session_id_1, &nonce_1, &public_key_2, &enckey)
            .expect_err("Can modify an already existing nonce");
        multi_sig_service
            .add_nonce(&session_id_2, &nonce_1, &public_key_1, &enckey)
            .expect("Unable to add nonce to session 2");

        let partial_signature_1 = multi_sig_service
            .partial_signature(&session_id_1, &enckey)
            .expect("Unable to generate partial signature for session 1");
        assert!(
            multi_sig_service
                .partial_signature(&session_id_1, &enckey)
                .is_ok(),
            "Not able to retrieve partial signatures multiple times"
        );

        let partial_signature_2 = multi_sig_service
            .partial_signature(&session_id_2, &enckey)
            .expect("Unable to generate partial signature for session 2");

        multi_sig_service
            .add_partial_signature(&session_id_1, partial_signature_2, &public_key_2, &enckey)
            .expect("Unable to add partial signature to session 1");
        multi_sig_service
            .add_partial_signature(&session_id_2, partial_signature_1, &public_key_1, &enckey)
            .expect("Unable to add partial signature to session 2");

        let signature_1 = multi_sig_service.signature(&session_id_1, &enckey).unwrap();
        let signature_2 = multi_sig_service.signature(&session_id_2, &enckey).unwrap();

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
