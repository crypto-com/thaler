use crate::ciphersuite::HkdfExt;
use hkdf::{Hkdf, InvalidPrkLength};
use secrecy::{ExposeSecret, SecretVec};
use sha2::digest::{generic_array, BlockInput, FixedOutput, Reset, Update};

pub struct EpochSecrets<D: BlockInput + FixedOutput + Reset + Update + Default + Clone> {
    pub init_secret: SecretVec<u8>,
    pub confirmation_key: SecretVec<u8>,
    pub epoch_secret: (SecretVec<u8>, Hkdf<D>),
}

impl<D: BlockInput + FixedOutput + Reset + Update + Default + Clone> EpochSecrets<D> {
    pub fn get_epoch_secret(prk: &[u8]) -> Result<Hkdf<D>, InvalidPrkLength> {
        Hkdf::<D>::from_prk(prk)
    }

    pub fn new(group_context_hash: Vec<u8>) -> Result<Self, hkdf::InvalidLength> {
        use generic_array::typenum::Unsigned;
        let init_commit_secret = SecretVec::new(vec![0u8; D::OutputSize::to_usize()]);
        Self::generate(&init_commit_secret, group_context_hash, &init_commit_secret)
    }

    pub fn from_epoch_secret(
        epoch_secret: (SecretVec<u8>, Hkdf<D>),
        group_context_hash: Vec<u8>,
    ) -> Result<Self, hkdf::InvalidLength> {
        use generic_array::typenum::Unsigned;
        let secret_len = D::OutputSize::to_u16();
        let confirmation_key =
            epoch_secret
                .1
                .derive_secret(group_context_hash.clone(), "confirm", secret_len)?;
        let init_secret =
            epoch_secret
                .1
                .derive_secret(group_context_hash.clone(), "init", secret_len)?;
        let _application_secret = SecretVec::new(epoch_secret.1.derive_secret(
            group_context_hash,
            "app",
            secret_len,
        )?);

        Ok(Self {
            init_secret: SecretVec::new(init_secret),
            confirmation_key: SecretVec::new(confirmation_key),
            epoch_secret,
        })
    }

    fn generate(
        init_secret: &SecretVec<u8>,
        group_context_hash: Vec<u8>,
        commit_secret: &SecretVec<u8>,
    ) -> Result<Self, hkdf::InvalidLength> {
        let early_secret = Hkdf::<D>::new(None, &init_secret.expose_secret());
        use generic_array::typenum::Unsigned;
        let secret_len = D::OutputSize::to_u16();
        let derived_secret = early_secret.derive_secret(b"".to_vec(), "derived", secret_len)?;
        let (es, epoch_secret) =
            Hkdf::<D>::extract(Some(&commit_secret.expose_secret()), &derived_secret);
        // FIXME: these are to be used later
        let _sender_data_secret =
            epoch_secret.derive_secret(group_context_hash.clone(), "sender data", secret_len);
        let _handshake_secret =
            epoch_secret.derive_secret(group_context_hash.clone(), "handshake", secret_len);
        let _exporter_secret =
            epoch_secret.derive_secret(group_context_hash.clone(), "exporter", secret_len);
        let _application_secret = SecretVec::new(epoch_secret.derive_secret(
            group_context_hash.clone(),
            "app",
            secret_len,
        )?);
        let confirmation_key =
            epoch_secret.derive_secret(group_context_hash.clone(), "confirm", secret_len)?;
        let init_secret = epoch_secret.derive_secret(group_context_hash, "init", secret_len)?;
        Ok(Self {
            init_secret: SecretVec::new(init_secret),
            confirmation_key: SecretVec::new(confirmation_key),
            epoch_secret: (SecretVec::new(es.to_vec()), epoch_secret),
        })
    }

    pub fn derive_welcome_secrets(
        epoch_secret: &Hkdf<D>,
        key_size: usize,
        nonce_size: usize,
    ) -> Result<(SecretVec<u8>, Vec<u8>), hkdf::InvalidLength> {
        use generic_array::typenum::Unsigned;
        let mut welcome_secret = vec![0u8; D::OutputSize::to_usize()];
        // TODO: use generic array for the sizes / to prevent invalid size?
        epoch_secret.expand(b"mls 1.0 welcome", &mut welcome_secret)?;
        let welcome_secret = Hkdf::<D>::new(None, &welcome_secret);
        let mut nonce = vec![0u8; nonce_size];
        welcome_secret.expand(b"nonce", &mut nonce)?;
        let mut key = vec![0u8; key_size];
        welcome_secret.expand(b"key", &mut key)?;
        Ok((SecretVec::new(key), nonce))
    }

    pub fn get_welcome_secret_key_nonce(
        &self,
        key_size: usize,
        nonce_size: usize,
    ) -> Result<(SecretVec<u8>, Vec<u8>), hkdf::InvalidLength> {
        Self::derive_welcome_secrets(&self.epoch_secret.1, key_size, nonce_size)
    }

    pub fn generate_new_epoch_secrets(
        &self,
        commit_secret: &SecretVec<u8>,
        updated_group_context_hash: Vec<u8>,
    ) -> Result<Self, hkdf::InvalidLength> {
        Self::generate(&self.init_secret, updated_group_context_hash, commit_secret)
    }

    pub fn compute_confirmation(&self, confirmed_transcript: &[u8]) -> Vec<u8> {
        // HMAC(confirmation_key, GroupContext.confirmed_transcript_hash)
        let (confirmation, _) = Hkdf::<D>::extract(
            Some(self.confirmation_key.expose_secret()),
            confirmed_transcript,
        );
        confirmation.to_vec()
    }
}
