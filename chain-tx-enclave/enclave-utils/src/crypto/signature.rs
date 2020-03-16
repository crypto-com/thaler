use std::{fs::read, path::Path};

use ring::signature::{self, RsaKeyPair, UnparsedPublicKey};
use thiserror::Error;

use crate::crypto::{pem_parser::pem_to_der, random::RandomState};

pub type Signature = Vec<u8>; // variable length, depending on RSA parameters

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("UTF-8 parsing error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("Invalid signing key: {0}")]
    InvalidSigningKey(ring::error::KeyRejected),
    #[error("Bad signature")]
    BadSignature,
    #[error("Out of memory")]
    OutOfMemory,
}

pub struct VerificationKey {
    key: Vec<u8>,
}

impl VerificationKey {
    pub fn new_from_der(public_key_der: &[u8]) -> Result<Self, SignatureError> {
        Ok(Self {
            key: public_key_der.to_vec(),
        })
    }

    pub fn new_from_pem(public_key_pem: &str) -> Result<Self, SignatureError> {
        Ok(Self {
            key: pem_to_der(public_key_pem)?,
        })
    }

    pub fn new_from_der_file(public_key_der: &Path) -> Result<Self, SignatureError> {
        Ok(Self {
            key: read(public_key_der)?,
        })
    }

    pub fn new_from_pem_file(public_key_pem: &Path) -> Result<Self, SignatureError> {
        let pem = String::from_utf8(read(public_key_pem)?)?;
        Self::new_from_pem(&pem)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &self.key);
        public_key
            .verify(message, signature)
            .map_err(|_| SignatureError::BadSignature)
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

pub struct SigningKey {
    key_pair: RsaKeyPair,
}

impl SigningKey {
    pub fn new_from_der_file(private_key_der: &Path) -> Result<Self, SignatureError> {
        let private_key_der = read(&private_key_der)?;
        let key_pair =
            RsaKeyPair::from_der(&private_key_der).map_err(SignatureError::InvalidSigningKey)?;
        Ok(Self { key_pair })
    }

    pub fn new_from_pem_file(private_key_pem: &Path) -> Result<Self, SignatureError> {
        let private_key_pem = String::from_utf8(read(&private_key_pem)?)?;
        let private_key_der = pem_to_der(&private_key_pem)?;
        let key_pair =
            RsaKeyPair::from_der(&private_key_der).map_err(SignatureError::InvalidSigningKey)?;
        Ok(Self { key_pair })
    }

    pub fn sign(&self, msg: &[u8], rng: &RandomState) -> Result<Signature, SignatureError> {
        let mut signature = vec![0; self.key_pair.public_modulus_len()];
        self.key_pair
            .sign(
                &signature::RSA_PKCS1_SHA256,
                rng.as_ref(),
                msg,
                &mut signature,
            )
            .map_err(|_| SignatureError::OutOfMemory)?;
        Ok(signature)
    }
}
