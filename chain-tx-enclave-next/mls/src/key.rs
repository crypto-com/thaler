//! Implements P-256 keys
use std::fmt::{Debug, Formatter, Result as FmtResult};

use generic_array::GenericArray;
use hpke::{kex::KeyExchange, Deserializable, HpkeError, Kem, Serializable};
use ring::{
    error, rand as ringrang,
    signature::{
        EcdsaKeyPair, KeyPair, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING,
    },
};
use secrecy::ExposeSecret;

use crate::ciphersuite::{CipherSuite, GenericSecret, Kex, PrivateKey, PublicKey, SecretValue};
use crate::{Codec, Reader};

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
pub struct HPKEPublicKey<CS: CipherSuite>(PublicKey<CS>);

impl<CS: CipherSuite> HPKEPublicKey<CS> {
    pub fn kex_pubkey(&self) -> &PublicKey<CS> {
        &self.0
    }

    pub fn marshal(&self) -> GenericArray<u8, <PublicKey<CS> as Serializable>::OutputSize> {
        self.0.to_bytes()
    }
}

impl<CS: CipherSuite> Debug for HPKEPublicKey<CS> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("HPKEPublicKey")
            .field("0", &self.0.to_bytes()) // TODO: hex?
            .finish()
    }
}

impl<CS: CipherSuite> Codec for HPKEPublicKey<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let payload = self.0.to_bytes();
        let len = payload.len();
        debug_assert!(len <= 0xffff);
        (len as u16).encode(bytes);
        bytes.extend_from_slice(&payload);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = u16::read(r)? as usize;
        let slice = r.take(len)?;
        let pk = <PublicKey<CS>>::from_bytes(slice).ok()?;
        Some(Self(pk))
    }
}

/// hpke private key
/// used for obtaining the initial sealed secrets (HPKE)
pub struct HPKEPrivateKey<CS: CipherSuite>(PrivateKey<CS>);

impl<CS: CipherSuite> HPKEPrivateKey<CS> {
    pub fn kex_secret(&self) -> &PrivateKey<CS> {
        &self.0
    }

    pub fn unmarshal(secret: &[u8]) -> Result<Self, HpkeError> {
        <PrivateKey<CS>>::from_bytes(secret).map(Self)
    }

    pub fn marshal_arr_unsafe(
        &self,
    ) -> GenericArray<u8, <PrivateKey<CS> as Serializable>::OutputSize> {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> HPKEPublicKey<CS> {
        HPKEPublicKey(<Kex<CS> as KeyExchange>::sk_to_pk(&self.0))
    }
}

pub fn gen_keypair<CS: CipherSuite>() -> (HPKEPrivateKey<CS>, HPKEPublicKey<CS>) {
    derive_keypair(&GenericSecret::gen())
}

pub fn derive_keypair<CS: CipherSuite>(
    path_secret: &SecretValue<CS>,
) -> (HPKEPrivateKey<CS>, HPKEPublicKey<CS>) {
    let (hpke_secret, hpke_public) = <CS::Kem as Kem>::derive_keypair(
        CS::derive_secret(path_secret, "node")
            .expose_secret()
            .as_ref(),
    );
    (HPKEPrivateKey(hpke_secret), HPKEPublicKey(hpke_public))
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
