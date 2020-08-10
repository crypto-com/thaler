use secp256k1::schnorrsig::SchnorrSignature;

use chain_core::common::H256;
use client_common::{
    ErrorKind, PrivateKey, PublicKey, Result, ResultExt, SecKey, SecureStorage, Storage,
};

use crate::multi_sig::MultiSigBuilder;

const KEYSPACE: &str = "core_multi_sig_address";

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
        signer_public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        self_private_key: PrivateKey,
        enckey: &SecKey,
    ) -> Result<H256> {
        let session = MultiSigBuilder::new(
            message,
            signer_public_keys,
            self_public_key,
            self_private_key,
        )?;

        let session_id = session.id();
        self.set_session(&session_id, session, enckey)?;

        Ok(session_id)
    }

    /// Returns nonce commitment of self
    pub fn nonce_commitment(&self, session_id: &H256, enckey: &SecKey) -> Result<H256> {
        let mut session = self.get_session(session_id, enckey)?;
        let nonce_commitment = session.nonce_commitment()?;

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
                let session_bytes = value.chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        format!("Session with ID ({}) not found", hex::encode(session_id)),
                    )
                })?;
                let mut session =
                    MultiSigBuilder::from_incomplete_insecure(session_bytes.to_vec())?;
                session.add_nonce_commitment(public_key, nonce_commitment)?;

                Ok(Some(session.to_incomplete()))
            })
            .map(|_| ())
    }

    /// Returns nonce of self. This function will fail if nonce commitments from all co-signers are not received.
    pub fn nonce(&self, session_id: &H256, enckey: &SecKey) -> Result<H256> {
        let mut session = self.get_session(session_id, enckey)?;
        let nonce = session.nonce()?;

        self.set_session(session_id, session, enckey)?;
        Ok(nonce)
    }

    /// Adds a nonce from a public key to session with given id
    pub fn add_nonce(
        &self,
        session_id: &H256,
        nonce: &H256,
        public_key: &PublicKey,
        enckey: &SecKey,
    ) -> Result<()> {
        self.storage
            .fetch_and_update_secure(KEYSPACE, session_id, enckey, |value| {
                let session_bytes = value.chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        format!("Session with ID ({}) not found", hex::encode(session_id)),
                    )
                })?;
                let mut session =
                    MultiSigBuilder::from_incomplete_insecure(session_bytes.to_vec())?;
                session.add_nonce(public_key, nonce)?;

                Ok(Some(session.to_incomplete()))
            })
            .map(|_| ())
    }

    /// Returns partial signature of self. This function will fail if nonces from all co-signers are not received.
    pub fn partial_signature(&self, session_id: &H256, enckey: &SecKey) -> Result<H256> {
        let mut session = self.get_session(session_id, enckey)?;
        let partial_signature = session.partial_signature()?;

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
                let session_bytes = value.chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        format!("Session with ID ({}) not found", hex::encode(session_id)),
                    )
                })?;
                let mut session =
                    MultiSigBuilder::from_incomplete_insecure(session_bytes.to_vec())?;
                session.add_partial_signature(public_key, partial_signature)?;

                Ok(Some(session.to_incomplete()))
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
    fn get_session(&self, session_id: &H256, enckey: &SecKey) -> Result<MultiSigBuilder> {
        let session_bytes = self
            .storage
            .get_secure(KEYSPACE, session_id, enckey)?
            .chain(|| {
                (
                    ErrorKind::InvalidInput,
                    format!("Session with ID ({}) not found", hex::encode(session_id)),
                )
            })?;
        MultiSigBuilder::from_incomplete_insecure(session_bytes)
    }

    /// Persists a session in storage
    fn set_session(
        &self,
        session_id: &H256,
        session: MultiSigBuilder,
        enckey: &SecKey,
    ) -> Result<()> {
        self.storage
            .set_secure(KEYSPACE, session_id, session.to_incomplete(), enckey)
            .map(|_| ())
    }
}

#[cfg(test)]
mod multi_sig_session_service_tests {
    use super::*;

    use secp256k1::schnorrsig::schnorr_verify;
    use secp256k1::Message;
    use secstr::SecUtf8;

    use client_common::{seckey::derive_enckey, storage::MemoryStorage, SECP};

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

        schnorr_verify(
            secp256k1::SECP256K1,
            &message,
            &signature_1,
            &combined_public_key.into(),
        )
        .expect("Invalid signature");
    }
}
