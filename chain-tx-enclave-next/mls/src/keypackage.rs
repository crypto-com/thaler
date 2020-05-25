//! Key package of mls protocol (draft-ietf-mls-protocol.md#key-packages)
use std::time::{Duration, UNIX_EPOCH};

use ra_client::{EnclaveCertVerifier, EnclaveCertVerifierConfig, EnclaveCertVerifierError};
#[cfg(target_env = "sgx")]
use ra_enclave::{Certificate, EnclaveRaContext, EnclaveRaContextError};
use rustls::internal::msgs::codec::{self, Codec, Reader};
#[cfg(target_env = "sgx")]
use x509_parser::{parse_x509_der, x509};

use crate::credential::Credential;
use crate::extensions::{self as ext, MLSExtension};
use crate::key::{PrivateKey, PublicKey};
use crate::utils;

pub type ProtocolVersion = u8;
pub type Timespec = u64;
pub type CipherSuite = u16;

pub const PROTOCOL_VERSION_MLS10: ProtocolVersion = 0;
pub const DEFAULT_LIFE_TIME: Timespec = 30 * 24 * 3600;
pub const MLS10_128_DHKEMP256_AES128GCM_SHA256_P256: CipherSuite = 2;
pub const CREDENTIAL_TYPE_X509: u8 = 1;

/// spec: draft-ietf-mls-protocol.md#key-packages
#[derive(Debug)]
pub struct KeyPackagePayload {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub init_key: PublicKey,
    pub credential: Credential,
    pub extensions: Vec<ext::ExtensionEntry>,
}

impl Codec for KeyPackagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.version.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.init_key.encode(bytes);
        self.credential.encode(bytes);
        codec::encode_vec_u16(bytes, &self.extensions);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let version = ProtocolVersion::read(r)?;
        let cipher_suite = CipherSuite::read(r)?;
        let init_key = PublicKey::read(r)?;
        let credential = Credential::read(r)?;
        let extensions = codec::read_vec_u16(r)?;
        Some(Self {
            version,
            cipher_suite,
            init_key,
            credential,
            extensions,
        })
    }
}

impl KeyPackagePayload {
    fn find_extension<T: MLSExtension>(&self) -> Result<T, FindExtensionError> {
        let data = self
            .extensions
            .iter()
            .filter_map(|ext::ExtensionEntry { etype, data }| {
                if *etype == T::EXTENSION_TYPE {
                    Some(data)
                } else {
                    None
                }
            })
            .next()
            .ok_or(FindExtensionError(T::EXTENSION_TYPE, "extension not found"))?;
        // FIXME check remaining data, need support from Codec trait
        <T>::read_bytes(data).ok_or(FindExtensionError(
            T::EXTENSION_TYPE,
            "extension decoding fails",
        ))
    }

    /// Verify key package payload
    pub fn verify(&self, ra_config: EnclaveCertVerifierConfig, now: Timespec) -> Result<(), Error> {
        if self.cipher_suite != MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 {
            return Err(Error::UnsupportedCipherSuite(self.cipher_suite));
        }

        // Check for required extensions
        let versions = self.find_extension::<ext::SupportedVersionsExt>()?;
        if !versions.0.contains(&PROTOCOL_VERSION_MLS10) {
            return Err(Error::InvalidSupportedVersions);
        }

        let ciphersuites = self.find_extension::<ext::SupportedCipherSuitesExt>()?;
        if !ciphersuites
            .0
            .contains(&MLS10_128_DHKEMP256_AES128GCM_SHA256_P256)
        {
            return Err(Error::InvalidSupportedCipherSuites);
        }

        let lifetime = self.find_extension::<ext::LifeTimeExt>()?;
        if now < lifetime.not_before {
            return Err(Error::NotBefore(lifetime.not_before));
        }
        if now > lifetime.not_after {
            return Err(Error::NotAfter(lifetime.not_after));
        }

        let x509 = self.credential.x509().ok_or(Error::InvalidCredential)?;

        let verifier = EnclaveCertVerifier::new(ra_config).map_err(Error::VerifierInitError)?;
        let cert_pubkey = verifier
            .verify_cert(x509, (UNIX_EPOCH + Duration::from_secs(now)).into())
            .map_err(Error::CertificateVerifyError)?;
        if cert_pubkey.as_slice() != self.init_key.as_ref() {
            return Err(Error::InitKeyDontMatch);
        }
        Ok(())
    }
}

/// Key package, only send `(payload, signature)` to other nodes.
/// spec: draft-ietf-mls-protocol.md#key-packages
#[derive(Debug)]
pub struct KeyPackage {
    pub payload: KeyPackagePayload,
    pub signature: Vec<u8>,
}

impl Codec for KeyPackage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
        utils::encode_vec_u8_u16(bytes, &self.signature);
    }
    fn read(r: &mut Reader) -> Option<Self> {
        let payload = KeyPackagePayload::read(r)?;
        let signature = utils::read_vec_u8_u16(r)?;
        Some(Self { payload, signature })
    }
}

impl KeyPackage {
    /// Verify key package and signature
    pub fn verify(&self, ra_config: EnclaveCertVerifierConfig, now: Timespec) -> Result<(), Error> {
        self.payload.verify(ra_config, now)?;
        self.payload
            .init_key
            .verify_signature(&self.payload.get_encoding(), &self.signature)
            .map_err(Error::SignatureVerifyError)
    }
}

pub struct OwnedKeyPackage {
    pub keypackage: KeyPackage,
    pub private_key: PrivateKey,
}

impl OwnedKeyPackage {
    /// Create key package in enclave
    #[cfg(target_env = "sgx")]
    pub fn new(ra_ctx: EnclaveRaContext) -> Result<Self, EnclaveRaContextError> {
        let Certificate {
            certificate,
            private_key,
            ..
        } = ra_ctx.get_certificate()?;

        let (_, cert) = parse_x509_der(&certificate.0).expect("invalid cert");
        let x509::Validity {
            not_before,
            not_after,
        } = &cert.tbs_certificate.validity;

        let extensions = vec![
            ext::SupportedVersionsExt(vec![PROTOCOL_VERSION_MLS10]).entry(),
            ext::SupportedCipherSuitesExt(vec![MLS10_128_DHKEMP256_AES128GCM_SHA256_P256]).entry(),
            ext::LifeTimeExt::new(not_before.to_timespec().sec, not_after.to_timespec().sec)
                .entry(),
        ];

        let private_key = PrivateKey::from_pkcs8(&private_key.0).expect("invalid private key");
        let payload = KeyPackagePayload {
            version: PROTOCOL_VERSION_MLS10,
            cipher_suite: MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
            init_key: private_key.public_key(),
            credential: Credential::X509(certificate.0),
            extensions,
        };

        // sign payload
        let signature = private_key.sign(&payload.get_encoding());

        Ok(Self {
            keypackage: KeyPackage { payload, signature },
            private_key,
        })
    }
}

/// Error type for key package verification.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("signature verify error: {0}")]
    SignatureVerifyError(ring::error::Unspecified),
    #[error("{0}")]
    FindExtensionError(#[from] FindExtensionError),
    #[error("invalid supported versions")]
    InvalidSupportedVersions,
    #[error("invalid supported cipher suites")]
    InvalidSupportedCipherSuites,
    #[error("invalid credential, only support X509")]
    InvalidCredential,
    #[error("key package can't be used after timestamp: {0}")]
    NotAfter(Timespec),
    #[error("key package can't be used before timestamp: {0}")]
    NotBefore(Timespec),
    #[error("certificate verifier initialize error: {0}")]
    VerifierInitError(EnclaveCertVerifierError),
    #[error("certificate verify error: {0}")]
    CertificateVerifyError(EnclaveCertVerifierError),
    #[error("unsupported cipher suite: {0}")]
    UnsupportedCipherSuite(CipherSuite),
    #[error("init key and credential public key don't match")]
    InitKeyDontMatch,
}

#[derive(thiserror::Error, Debug)]
#[error("find extension error: {0:?}, {1}")]
pub struct FindExtensionError(ext::ExtensionType, &'static str);
