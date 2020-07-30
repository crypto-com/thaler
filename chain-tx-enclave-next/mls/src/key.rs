//! Implements P-256 keys
use hpke::{
    kex::{Marshallable, Unmarshallable},
    HpkeError,
};
use rand::thread_rng;
use ring::{
    error, rand as ringrang,
    signature::{
        EcdsaKeyPair, KeyPair, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING,
    },
};
use rustls::internal::msgs::codec::{Codec, Reader};
use secrecy::SecretVec;
use std::fmt::{Debug, Formatter, Result as FmtResult};

/// p-256 public key
/// used in the credential / for signature verification
///
/// TODO: Use `[u8; 65]` instead of `Vec<u8>`?
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct IdentityPublicKey(Vec<u8>);

impl IdentityPublicKey {
    /// currently as ring's ECDSA_P256_SHA256_ASN1.verify will parse and check the pubkey
    pub fn new_unsafe(unparsed_key: Vec<u8>) -> Self {
        Self(unparsed_key)
    }

    /// Verify P-256 signature
    /// FIXME: types to distinguish between signature and message payloads
    pub fn verify_signature(&self, msg: &[u8], sig: &[u8]) -> Result<(), error::Unspecified> {
        ECDSA_P256_SHA256_ASN1.verify(self.0.as_slice().into(), msg.into(), sig.into())
    }
}

impl AsRef<[u8]> for IdentityPublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Codec for IdentityPublicKey {
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

/// p-256 public key
/// init key used in asymmetric encryption (HPKE)
#[derive(Clone)]
pub struct HPKEPublicKey(<hpke::kex::DhP256 as hpke::KeyExchange>::PublicKey);

impl HPKEPublicKey {
    pub fn kex_pubkey(&self) -> &<hpke::kex::DhP256 as hpke::KeyExchange>::PublicKey {
        &self.0
    }

    pub fn marshal(&self) -> Vec<u8> {
        self.0.marshal().to_vec()
    }
}

impl Debug for HPKEPublicKey {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("HPKEPublicKey")
            .field("0", &self.0.marshal()) // TODO: hex?
            .finish()
    }
}

impl Codec for HPKEPublicKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let payload = self.0.marshal();
        let len = payload.len();
        debug_assert!(len <= 0xffff);
        (len as u16).encode(bytes);
        bytes.extend_from_slice(&payload);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = u16::read(r)? as usize;
        let slice = r.take(len)?;
        let pk = <hpke::kex::DhP256 as hpke::KeyExchange>::PublicKey::unmarshal(slice).ok()?;
        Some(Self(pk))
    }
}

/// p-256 private key
/// used for obtaining the initial sealed secrets (HPKE)
pub struct HPKEPrivateKey(<hpke::kex::DhP256 as hpke::KeyExchange>::PrivateKey);

impl HPKEPrivateKey {
    pub fn generate() -> (HPKEPrivateKey, HPKEPublicKey) {
        let (hpke_secret, hpke_public) =
            <hpke::kem::DhP256HkdfSha256 as hpke::Kem>::gen_keypair(&mut thread_rng());

        (HPKEPrivateKey(hpke_secret), HPKEPublicKey(hpke_public))
    }

    pub fn derive(ikm: &[u8]) -> Self {
        Self(<hpke::kem::DhP256HkdfSha256 as hpke::Kem>::derive_keypair(ikm).0)
    }

    pub fn kex_secret(&self) -> &<hpke::kex::DhP256 as hpke::KeyExchange>::PrivateKey {
        &self.0
    }

    pub fn unmarshal(secret: &[u8]) -> Result<Self, HpkeError> {
        <hpke::kex::DhP256 as hpke::KeyExchange>::PrivateKey::unmarshal(secret).map(Self)
    }

    pub fn marshal(&self) -> SecretVec<u8> {
        <SecretVec<u8>>::new(
            <hpke::kex::DhP256 as hpke::KeyExchange>::PrivateKey::marshal(&self.0).to_vec(),
        )
    }

    pub fn public_key(&self) -> HPKEPublicKey {
        HPKEPublicKey(<hpke::kex::DhP256 as hpke::KeyExchange>::sk_to_pk(&self.0))
    }
}

/// p-256 private key (key pair)
/// used for signing
pub struct IdentityPrivateKey(EcdsaKeyPair);

impl IdentityPrivateKey {
    pub fn from_pkcs8(data: &[u8]) -> Result<Self, error::KeyRejected> {
        let ringkp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, data)?;
        Ok(Self(ringkp))
    }

    pub fn public_key_raw(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.0.public_key().as_ref().to_vec())
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, error::Unspecified> {
        Ok(self
            .0
            .sign(&ringrang::SystemRandom::new(), msg)?
            .as_ref()
            .to_vec())
    }
}
