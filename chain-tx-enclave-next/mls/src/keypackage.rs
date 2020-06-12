//! Key package of mls protocol (draft-ietf-mls-protocol.md#key-packages)
#[cfg(target_env = "sgx")]
use std::convert::TryInto;
use std::time::{Duration, UNIX_EPOCH};

use ra_client::{AttestedCertVerifier, CertVerifyResult, EnclaveCertVerifierError};
#[cfg(target_env = "sgx")]
use ra_enclave::{Certificate, EnclaveRaContext, EnclaveRaContextError};
use rustls::internal::msgs::codec::{self, Codec, Reader};
#[cfg(target_env = "sgx")]
use x509_parser::{parse_x509_der, x509};

use crate::credential::Credential;
use crate::extensions::{self as ext, MLSExtension};
use crate::key::{HPKEPrivateKey, HPKEPublicKey, IdentityPrivateKey, IdentityPublicKey};
use crate::utils;
use core::cmp::Ordering;

pub type ProtocolVersion = u8;
pub type Timespec = u64;
pub type CipherSuite = u16;

pub const PROTOCOL_VERSION_MLS10: ProtocolVersion = 0;
pub const DEFAULT_LIFE_TIME: Timespec = 90 * 24 * 3600; // certificate has 90 days valid duration
pub const MLS10_128_DHKEMP256_AES128GCM_SHA256_P256: CipherSuite = 2;
pub const CREDENTIAL_TYPE_X509: u8 = 1;

/// spec: draft-ietf-mls-protocol.md#key-packages
#[derive(Debug, Clone)]
pub struct KeyPackagePayload {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub init_key: HPKEPublicKey,
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
        let init_key = HPKEPublicKey::read(r)?;
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
    pub fn find_extension<T: MLSExtension>(&self) -> Result<T, FindExtensionError> {
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
    pub fn verify(
        &self,
        ra_verifier: &impl AttestedCertVerifier,
        now: Timespec,
    ) -> Result<CertVerifyResult, Error> {
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

        let info = ra_verifier
            .verify_attested_cert(x509, (UNIX_EPOCH + Duration::from_secs(now)).into())
            .map_err(Error::CertificateVerifyError)?;
        Ok(info)
    }
}

/// Key package, only send `(payload, signature)` to other nodes.
/// spec: draft-ietf-mls-protocol.md#key-packages
#[derive(Debug, Clone)]
pub struct KeyPackage {
    pub payload: KeyPackagePayload,
    pub signature: Vec<u8>,
}

impl Ord for KeyPackage {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.payload.version,
            self.payload.cipher_suite,
            self.payload.init_key.get_encoding(),
            &self.payload.credential,
            &self.payload.extensions,
            &self.signature,
        )
            .cmp(&(
                other.payload.version,
                other.payload.cipher_suite,
                other.payload.init_key.get_encoding(),
                &other.payload.credential,
                &other.payload.extensions,
                &other.signature,
            ))
    }
}

impl PartialOrd for KeyPackage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for KeyPackage {
    fn eq(&self, other: &Self) -> bool {
        (
            self.payload.version,
            self.payload.cipher_suite,
            self.payload.init_key.get_encoding(),
            &self.payload.credential,
            &self.payload.extensions,
            &self.signature,
        ) == (
            other.payload.version,
            other.payload.cipher_suite,
            other.payload.init_key.get_encoding(),
            &other.payload.credential,
            &other.payload.extensions,
            &other.signature,
        )
    }
}

impl Eq for KeyPackage {}

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
    pub fn verify(
        &self,
        ra_verifier: &impl AttestedCertVerifier,
        now: Timespec,
    ) -> Result<CertVerifyResult, Error> {
        let info = self.payload.verify(ra_verifier, now)?;
        let public_key = IdentityPublicKey::new_unsafe(info.public_key.clone());
        public_key
            .verify_signature(&self.payload.get_encoding(), &self.signature)
            .map_err(Error::SignatureVerifyError)?;
        Ok(info)
    }
}

pub struct OwnedKeyPackage {
    pub keypackage: KeyPackage,
    pub credential_private_key: IdentityPrivateKey,
    pub init_private_key: HPKEPrivateKey,
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
            ext::LifeTimeExt::new(
                not_before.to_timespec().sec.try_into().unwrap(),
                not_after.to_timespec().sec.try_into().unwrap(),
            )
            .entry(),
        ];

        let private_key =
            IdentityPrivateKey::from_pkcs8(&private_key.0).expect("invalid private key");
        let (hpke_secret, hpke_public) = HPKEPrivateKey::generate();
        let payload = KeyPackagePayload {
            version: PROTOCOL_VERSION_MLS10,
            cipher_suite: MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
            init_key: hpke_public,
            credential: Credential::X509(certificate.0),
            extensions,
        };

        // sign payload
        let signature = private_key.sign(&payload.get_encoding());

        Ok(Self {
            keypackage: KeyPackage { payload, signature },
            credential_private_key: private_key,
            init_private_key: hpke_secret,
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
    #[error("certificate verify error: {0}")]
    CertificateVerifyError(EnclaveCertVerifierError),
    #[error("unsupported cipher suite: {0}")]
    UnsupportedCipherSuite(CipherSuite),
    #[error("init key and credential public key don't match")]
    InitKeyDontMatch,
    #[error("duplicate key package")]
    DuplicateKeyPackage,
    #[error("key package not found")]
    KeyPackageNotFound,
    #[error("ratchet tree integrity check failed")]
    TreeIntegrityError,
    #[error("group info integrity check failed")]
    GroupInfoIntegrityError,
    #[error("Epoch does not match")]
    GroupEpochError,
    #[error("Commit processing error")]
    CommitError,
}

#[derive(thiserror::Error, Debug)]
#[error("find extension error: {0:?}, {1}")]
pub struct FindExtensionError(ext::ExtensionType, &'static str);
