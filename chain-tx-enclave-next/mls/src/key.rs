//! Implements P-256 keys
use ring::{
    error, rand,
    signature::{
        EcdsaKeyPair, KeyPair, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING,
    },
};
use rustls::internal::msgs::codec::{Codec, Reader};

/// p-256 public key
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    /// Verify P-256 signature
    /// FIXME: types to distinguish between signature and message payloads
    pub fn verify_signature(&self, msg: &[u8], sig: &[u8]) -> Result<(), error::Unspecified> {
        ECDSA_P256_SHA256_ASN1.verify(self.0.as_slice().into(), msg.into(), sig.into())
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Codec for PublicKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let len = self.0.len();
        debug_assert!(len <= 0xffff);
        (len as u16).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = u16::read(r)? as usize;
        r.take(len).map(|slice| Self(slice.to_vec()))
    }
}

/// p-256 private key (key pair)
pub struct PrivateKey(EcdsaKeyPair);

impl PrivateKey {
    pub fn from_pkcs8(data: &[u8]) -> Result<Self, error::KeyRejected> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, data).map(Self)
    }
    pub fn public_key_raw(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key().as_ref().to_vec())
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0
            .sign(&rand::SystemRandom::new(), msg)
            .unwrap()
            .as_ref()
            .to_vec()
    }
}
