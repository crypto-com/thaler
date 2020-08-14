use generic_array::GenericArray;
use rand::{thread_rng, RngCore};
use secrecy::{ExposeSecret, Secret};

use crate::ciphersuite::{
    AeadKeySize, AeadNonceSize, CipherSuite, HashValue, KeySecret, NodeSecret,
};

pub struct EpochSecrets<CS: CipherSuite> {
    pub init_secret: Secret<KeySecret<CS>>,
    pub confirmation_key: Secret<KeySecret<CS>>,
    pub joiner_secret: Secret<KeySecret<CS>>,
    pub epoch_secret: Secret<KeySecret<CS>>,
}

impl<CS: CipherSuite> EpochSecrets<CS> {
    pub fn new(group_context: &[u8]) -> Self {
        // * Init secret: a fresh random value of size `KDF.Nh`
        let mut init_secret = KeySecret::<CS>::default();
        thread_rng().fill_bytes(init_secret.as_mut());

        let init_commit_secret = NodeSecret::<CS>::default();
        Self::generate(&init_secret, &init_commit_secret, group_context)
    }

    /// A number of secrets are derived from the epoch secret for different purposes
    pub fn from_joiner_secret(joiner_secret: Secret<KeySecret<CS>>, ctx: &[u8]) -> Self {
        let member_secret = CS::extract_group_secret(
            None,
            CS::derive_group_secret(joiner_secret.expose_secret(), "member")
                .expose_secret()
                .as_ref(),
        );
        let epoch_secret = CS::extract_group_secret(
            Some(ctx),
            CS::derive_group_secret(member_secret.expose_secret(), "epoch")
                .expose_secret()
                .as_ref(),
        );

        // FIXME: these are to be used later
        let _sender_data_secret =
            CS::derive_group_secret(epoch_secret.expose_secret(), "sender data");
        let _handshake_secret = CS::derive_group_secret(epoch_secret.expose_secret(), "handshake");
        let _exporter_secret = CS::derive_group_secret(epoch_secret.expose_secret(), "exporter");

        let confirmation_key = CS::derive_group_secret(epoch_secret.expose_secret(), "confirm");
        let init_secret = CS::derive_group_secret(epoch_secret.expose_secret(), "init");

        Self {
            init_secret,
            confirmation_key,
            joiner_secret,
            epoch_secret,
        }
    }

    /// spec: draft-ietf-mls-protocol.md#key-schedule
    pub fn generate(
        init_secret: &KeySecret<CS>,
        commit_secret: &NodeSecret<CS>,
        group_context: &[u8],
    ) -> Self {
        let joiner_secret =
            CS::extract_group_secret(Some(init_secret.as_ref()), commit_secret.as_ref());
        Self::from_joiner_secret(joiner_secret, group_context)
    }

    pub fn get_welcome_secret_key_nonce(
        &self,
    ) -> (
        GenericArray<u8, AeadKeySize<CS>>,
        GenericArray<u8, AeadNonceSize<CS>>,
    ) {
        CS::derive_welcome_secret(self.joiner_secret.expose_secret())
    }

    pub fn compute_confirmation(&self, confirmed_transcript: &HashValue<CS>) -> HashValue<CS> {
        // HMAC(confirmation_key, GroupContext.confirmed_transcript_hash)
        HashValue(CS::extract(
            Some(self.confirmation_key.expose_secret().as_ref()),
            confirmed_transcript.as_ref(),
        ))
    }
}
