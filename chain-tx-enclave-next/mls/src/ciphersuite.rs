use std::convert::TryFrom;
use std::fmt::Debug;

use aead::{Aead, NewAead};
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use secrecy::ExposeSecret;
use secrecy::{CloneableSecret, Secret};
use sha2::digest::{FixedOutput, Update};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::utils;
use crate::{Codec, Reader};

/// spec: draft-ietf-mls-protocol.md#key-schedule
#[derive(Debug)]
struct KDFLabel {
    pub length: u16,
    // 7..255 -- prefixed with "mls10 "
    pub label: Vec<u8>,
    // 0..2^32-1
    pub context: Vec<u8>,
}

impl Codec for KDFLabel {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.length.encode(bytes);
        utils::encode_vec_u8_u8(bytes, &self.label);
        utils::encode_vec_u32(bytes, &self.context);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let length = u16::read(r)?;
        let label = utils::read_vec_u8_u8(r)?;
        let context: Vec<u8> = utils::read_vec_u32(r)?;
        Some(Self {
            length,
            label,
            context,
        })
    }
}

pub type CipherSuiteTag = u16;

/// the dependency traits are for deriving instances
pub trait CipherSuite: Debug + Clone + Default + Sized {
    type Kem: hpke::Kem;
    type Kdf: hpke::kdf::Kdf;
    type Aead: hpke::aead::Aead;

    fn tag() -> CipherSuiteTag;

    fn hash(data: &[u8]) -> HashValue<Self> {
        let mut hasher = HashImpl::<Self>::default();
        Update::update(&mut hasher, data);
        HashValue(hasher.finalize_fixed())
    }

    /// spec: draft-ietf-mls-protocol.md#ratchet-tree-evolve
    /// extract and expand
    fn derive_path_secret(secret: &NodeSecret<Self>) -> Secret<NodeSecret<Self>> {
        // extract
        let hkdf = Hkdf::<Self>::new(None, secret.as_ref());

        // expand
        let labeled_payload = KDFLabel {
            length: SecretSize::<Self>::to_u16(),
            label: b"mls10 path".to_vec(),
            context: vec![],
        }
        .get_encoding();

        // TODO how to statically assert this?
        assert!(SecretSize::<Self>::to_usize() <= HashSize::<Self>::to_usize() * 255);
        let mut okm = NodeSecret::<Self>::default();
        hkdf.expand(&labeled_payload, okm.as_mut())
            .expect("invariant asserted");
        Secret::new(okm)
    }

    /// spec: draft-ietf-mls-protocol.md#key-schedule
    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> GenericArray<u8, HashSize<Self>> {
        let (prk, _) = Hkdf::<Self>::extract(salt, ikm);
        prk
    }

    /// spec: draft-ietf-mls-protocol.md#key-schedule
    fn extract_group_secret(salt: Option<&[u8]>, ikm: &[u8]) -> Secret<KeySecret<Self>> {
        Secret::new(SecretValue(Self::extract(salt, ikm)))
    }

    /// spec: draft-ietf-mls-protocol.md#key-schedule
    fn derive_group_secret(prk: &KeySecret<Self>, label: &str) -> Secret<KeySecret<Self>> {
        let full_label = "mls10 ".to_owned() + label;
        let labeled_payload = KDFLabel {
            length: HashSize::<Self>::to_u16(),
            label: full_label.into_bytes().to_vec(),
            context: vec![],
        }
        .get_encoding();

        let mut okm = KeySecret::<Self>::default();
        let hkdf = Hkdf::<Self>::from_prk(prk.as_ref()).expect("size of prk == Kdf.Nk");
        hkdf.expand(&labeled_payload, okm.as_mut())
            .expect("size of okm == Kdf.Nk");
        Secret::new(okm)
    }

    /// spec: draft-ietf-mls-protocol.md#welcoming-new-members
    /// returns (welcome_key, welcome_nonce)
    fn derive_welcome_secret(
        joiner_secret: &KeySecret<Self>,
    ) -> (
        GenericArray<u8, AeadKeySize<Self>>,
        GenericArray<u8, AeadNonceSize<Self>>,
    ) {
        let prk = Self::derive_group_secret(joiner_secret, "welcome");
        let kdf =
            Hkdf::<Self>::from_prk(prk.expose_secret().as_ref()).expect("size of prk == Kdf.Nk");

        // TODO how to statically assert this?
        assert!(AeadNonceSize::<Self>::to_usize() <= HashSize::<Self>::to_usize() * 255);
        let mut nonce = GenericArray::default();
        kdf.expand(b"nonce", &mut nonce)
            .expect("invariant asserted");

        // TODO how to statically assert this?
        assert!(AeadKeySize::<Self>::to_usize() <= HashSize::<Self>::to_usize() * 255);
        let mut key = GenericArray::default();
        kdf.expand(b"key", key.as_mut())
            .expect("invariant asserted");

        (key, nonce)
    }
}

#[derive(Clone, Debug, Default, Ord, PartialOrd, Eq, PartialEq)]
pub struct P256 {}
impl CipherSuite for P256 {
    type Kem = hpke::kem::DhP256HkdfSha256;
    type Kdf = hpke::kdf::HkdfSha256;
    type Aead = hpke::aead::AesGcm128;

    fn tag() -> CipherSuiteTag {
        2
    }
}

pub type DefaultCipherSuite = P256;

pub type Kex<CS> = <<CS as CipherSuite>::Kem as hpke::Kem>::Kex;
// KEM.Nsk draft-ietf-mls-protocol.md#ratchet-tree-evolution
pub type SecretSize<CS> =
    <<Kex<CS> as hpke::KeyExchange>::PrivateKey as hpke::Marshallable>::OutputSize;
pub type HashImpl<CS> = <<CS as CipherSuite>::Kdf as hpke::kdf::Kdf>::HashImpl;
// KDF.Nh draft-ietf-mls-protocol.md#key-schedule
pub type HashSize<CS> = <HashImpl<CS> as FixedOutput>::OutputSize;
pub type AeadKeySize<CS> =
    <<<CS as CipherSuite>::Aead as hpke::aead::Aead>::AeadImpl as NewAead>::KeySize;
pub type AeadNonceSize<CS> =
    <<<CS as CipherSuite>::Aead as hpke::aead::Aead>::AeadImpl as Aead>::NonceSize;
pub type PrivateKey<CS> =
    <<<CS as CipherSuite>::Kem as hpke::Kem>::Kex as hpke::KeyExchange>::PrivateKey;
pub type PublicKey<CS> =
    <<<CS as CipherSuite>::Kem as hpke::Kem>::Kex as hpke::KeyExchange>::PublicKey;
pub type Hkdf<CS> = hkdf::Hkdf<HashImpl<CS>>;

/// Statically sized secret value
#[derive(Clone, Default)]
pub struct SecretValue<L: ArrayLength<u8>>(pub(crate) GenericArray<u8, L>);

impl<L: ArrayLength<u8>> AsMut<[u8]> for SecretValue<L> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<L: ArrayLength<u8>> AsRef<[u8]> for SecretValue<L> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<L: ArrayLength<u8>> Debug for SecretValue<L> {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        Ok(())
    }
}

impl<L: ArrayLength<u8>> Zeroize for SecretValue<L> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<L: ArrayLength<u8>> CloneableSecret for SecretValue<L> {}

impl<L: ArrayLength<u8>> Codec for SecretValue<L> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        utils::encode_vec_u8_u8(bytes, &self.0);
    }
    fn read(r: &mut Reader) -> Option<Self> {
        utils::read_arr_u8_u8(r).map(Self)
    }
}

/// spec: draft-ietf-mls-protocol.md#ratchet-tree-evolve
pub type NodeSecret<CS> = SecretValue<SecretSize<CS>>;
/// spec: draft-ietf-mls-protocol.md#key-schedule
pub type KeySecret<CS> = SecretValue<HashSize<CS>>;

#[derive(Clone, Debug, Default, Ord, PartialOrd, PartialEq, Eq)]
pub struct HashValue<CS: CipherSuite>(pub(crate) GenericArray<u8, HashSize<CS>>);

impl<CS: CipherSuite> AsRef<[u8]> for HashValue<CS> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<CS: CipherSuite> Codec for HashValue<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        utils::encode_vec_u8_u8(bytes, &self.0);
    }
    fn read(r: &mut Reader) -> Option<Self> {
        utils::read_arr_u8_u8(r).map(Self)
    }
}

impl<CS: CipherSuite> From<HashValue<CS>> for KeySecret<CS> {
    fn from(v: HashValue<CS>) -> Self {
        SecretValue(v.0)
    }
}

impl<CS: CipherSuite> ConstantTimeEq for HashValue<CS> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_ref().ct_eq(other.as_ref())
    }
}

impl<CS: CipherSuite> TryFrom<&[u8]> for HashValue<CS> {
    type Error = ();
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        GenericArray::from_exact_iter(value.iter().copied())
            .ok_or(())
            .map(Self)
    }
}
