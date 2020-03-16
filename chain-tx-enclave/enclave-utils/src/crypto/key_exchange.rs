use std::io::Write;

use ring::agreement::{
    agree_ephemeral, Algorithm, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256,
};
use thiserror::Error;

use crate::crypto::cmac::{Cmac, CmacError, MacTag};
use crate::crypto::random::RandomState;
use crate::crypto::signature::{Signature, SignatureError, SigningKey, VerificationKey};

const DHKE_PUBKEY_LEN: usize = 65;
const KDK_LEN: usize = std::mem::size_of::<MacTag>();

static KE_ALGORITHM: &Algorithm = &ECDH_P256;

pub type DHPublicKey = [u8; DHKE_PUBKEY_LEN];
pub type KDK = [u8; KDK_LEN];

#[derive(Debug, Error)]
pub enum KeyExchangeError {
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("Key generation error")]
    KeyGenerationError,
    #[error("CMAC error: {0}")]
    CmacError(#[from] CmacError),
    #[error("Key agreement error")]
    KeyAgreementError,
}

pub struct DHKeyPair {
    private_key: EphemeralPrivateKey,
    public_key: DHPublicKey,
}

impl DHKeyPair {
    pub fn generate_keypair(rng: &RandomState) -> Result<Self, KeyExchangeError> {
        let private_key = EphemeralPrivateKey::generate(KE_ALGORITHM, rng.as_ref())
            .map_err(|_| KeyExchangeError::KeyGenerationError)?;
        let mut public_key: DHPublicKey = [0; DHKE_PUBKEY_LEN];
        public_key.copy_from_slice(
            private_key
                .compute_public_key()
                .map_err(|_| KeyExchangeError::KeyGenerationError)?
                .as_ref(),
        );
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn public_key(&self) -> &DHPublicKey {
        &self.public_key
    }

    pub fn derive_key(self, peer_public_key: &DHPublicKey) -> Result<KDK, KeyExchangeError> {
        let public_key = UnparsedPublicKey::new(&KE_ALGORITHM, &peer_public_key[..]);

        agree_ephemeral(
            self.private_key,
            &public_key,
            KeyExchangeError::KeyAgreementError,
            |ikm| {
                let cmac = Cmac::new(&[0; KDK_LEN]);
                let kdk = cmac.sign(ikm)?;
                Ok(kdk)
            },
        )
    }
}

/// One-way authenticated DHKE. Alice (g_a) verifies and Bob (g_b) signs.
pub struct OneWayAuthenticatedDHKE {
    key_pair: DHKeyPair,
}

impl OneWayAuthenticatedDHKE {
    pub fn generate_keypair(rng: &RandomState) -> Result<Self, KeyExchangeError> {
        let key_pair = DHKeyPair::generate_keypair(rng)?;
        Ok(Self { key_pair })
    }

    pub fn get_public_key(&self) -> &DHPublicKey {
        &self.key_pair.public_key
    }

    /// Bob signs the (g_b, g_a).
    pub fn sign_and_derive(
        self,
        g_a: &DHPublicKey,
        signing_key: &SigningKey,
        rng: &RandomState,
    ) -> Result<(KDK, Signature), KeyExchangeError> {
        // Sign (g_b, g_a) with Bob's signing key
        let mut gb_ga = Vec::new();
        gb_ga.write_all(&self.key_pair.public_key).unwrap();
        gb_ga.write_all(g_a).unwrap();
        let sign_gb_ga = signing_key.sign(&gb_ga[..], rng)?;

        // Derive KDK
        let kdk = self.key_pair.derive_key(g_a)?;
        Ok((kdk, sign_gb_ga))
    }

    /// Alice verifies the (g_b, g_a).
    pub fn verify_and_derive(
        self,
        g_b: &DHPublicKey,
        sign_gb_ga: &Signature,
        verification_key: &VerificationKey,
    ) -> Result<KDK, KeyExchangeError> {
        // Verify (g_b, g_a) with Bob's verification key
        let mut gb_ga = Vec::new();
        gb_ga.write_all(g_b).unwrap();
        gb_ga.write_all(&self.key_pair.public_key).unwrap();
        verification_key.verify(&gb_ga[..], &sign_gb_ga[..])?;

        // Derive KDK
        self.key_pair.derive_key(g_b)
    }
}
