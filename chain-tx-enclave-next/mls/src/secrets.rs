use crate::ciphersuite::HkdfExt;
use hkdf::{Hkdf, InvalidPrkLength};
use secrecy::{ExposeSecret, SecretVec};
use sha2::digest::{generic_array, BlockInput, FixedOutput, Reset, Update};

pub struct EpochSecrets<D: BlockInput + FixedOutput + Reset + Update + Default + Clone> {
    pub init_secret: SecretVec<u8>,
    pub confirmation_key: SecretVec<u8>,
    pub joiner_secret: (SecretVec<u8>, Hkdf<D>),
    pub epoch_secret: (SecretVec<u8>, Hkdf<D>),
}

impl<D: BlockInput + FixedOutput + Reset + Update + Default + Clone> EpochSecrets<D> {
    pub fn get_epoch_secret(prk: &[u8]) -> Result<Hkdf<D>, InvalidPrkLength> {
        Hkdf::<D>::from_prk(prk)
    }

    pub fn new(group_context: &[u8]) -> Result<Self, hkdf::InvalidLength> {
        use generic_array::typenum::Unsigned;
        let init_commit_secret = SecretVec::new(vec![0u8; D::OutputSize::to_usize()]);
        Self::generate(&init_commit_secret, &init_commit_secret, group_context)
    }

    /// A number of secrets are derived from the epoch secret for different purposes
    pub fn from_joiner_secret(
        joiner_secret: (SecretVec<u8>, Hkdf<D>),
        ctx: &[u8],
    ) -> Result<Self, hkdf::InvalidLength> {
        let (_, member_secret) =
            Hkdf::<D>::extract(None, &joiner_secret.1.derive_secret("member")?);
        let (epoch_secret, epoch_hkdf) =
            Hkdf::<D>::extract(Some(ctx), &member_secret.derive_secret("epoch")?);

        // FIXME: these are to be used later
        let _sender_data_secret = epoch_hkdf.derive_secret("sender data");
        let _handshake_secret = epoch_hkdf.derive_secret("handshake");
        let _exporter_secret = epoch_hkdf.derive_secret("exporter");

        let confirmation_key = epoch_hkdf.derive_secret("confirm")?;
        let init_secret = epoch_hkdf.derive_secret("init")?;

        Ok(Self {
            init_secret: SecretVec::new(init_secret),
            confirmation_key: SecretVec::new(confirmation_key),
            joiner_secret,
            epoch_secret: (SecretVec::new(epoch_secret.to_vec()), epoch_hkdf),
        })
    }

    /// spec: draft-ietf-mls-protocol.md#key-schedule
    pub fn generate(
        init_secret: &SecretVec<u8>,
        commit_secret: &SecretVec<u8>,
        group_context: &[u8],
    ) -> Result<Self, hkdf::InvalidLength> {
        let (joiner_secret, joiner_hkdf) = Hkdf::<D>::extract(
            Some(init_secret.expose_secret()),
            commit_secret.expose_secret(),
        );
        Self::from_joiner_secret(
            (SecretVec::new(joiner_secret.to_vec()), joiner_hkdf),
            group_context,
        )
    }

    /// spec: draft-ietf-mls-protocol.md#key-schedule
    pub fn derive_welcome_secrets(
        joiner_secret: &Hkdf<D>,
        key_size: usize,
        nonce_size: usize,
    ) -> Result<(SecretVec<u8>, Vec<u8>), hkdf::InvalidLength> {
        // TODO: use generic array for the sizes / to prevent invalid size?
        let welcome_hkdf = Hkdf::<D>::from_prk(&joiner_secret.derive_secret("welcome")?)
            .expect("impossible: derive secret returns invalid data");
        let mut nonce = vec![0u8; nonce_size];
        welcome_hkdf.expand(b"nonce", &mut nonce)?;
        let mut key = vec![0u8; key_size];
        welcome_hkdf.expand(b"key", &mut key)?;
        Ok((SecretVec::new(key), nonce))
    }

    pub fn get_welcome_secret_key_nonce(
        &self,
        key_size: usize,
        nonce_size: usize,
    ) -> Result<(SecretVec<u8>, Vec<u8>), hkdf::InvalidLength> {
        Self::derive_welcome_secrets(&self.joiner_secret.1, key_size, nonce_size)
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
