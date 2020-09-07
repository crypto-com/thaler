//! Key package of mls protocol (draft-ietf-mls-protocol.md#key-packages)
#[cfg(target_env = "sgx")]
use std::convert::TryInto;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::time::{Duration, UNIX_EPOCH};

use once_cell::sync::Lazy;
use ra_client::{AttestedCertVerifier, CertVerifyResult};
#[cfg(target_env = "sgx")]
use ra_enclave::{Certificate, EnclaveRaContext, EnclaveRaContextError};
use secrecy::{ExposeSecret, Secret};
use subtle::ConstantTimeEq;
#[cfg(target_env = "sgx")]
use x509_parser::{error::X509Error, parse_x509_der, x509};

use crate::ciphersuite::{
    CipherSuite, CipherSuiteTag, DefaultCipherSuite, GenericSecret, SecretValue,
};
use crate::credential::Credential;
use crate::error::{FindExtensionError, KeyPackageError as Error};
use crate::extensions::{self as ext, ExtensionType, MLSExtension};
use crate::key::{
    derive_keypair, HPKEPrivateKey, HPKEPublicKey, IdentityPrivateKey, IdentityPublicKey,
};
use crate::utils;
use crate::{Codec, Reader};
use core::cmp::Ordering;

pub type ProtocolVersion = u8;
pub type Timespec = u64;

pub const PROTOCOL_VERSION_MLS10: ProtocolVersion = 1;
pub const DEFAULT_LIFE_TIME: Timespec = 90 * 24 * 3600; // certificate has 90 days valid duration
pub const CREDENTIAL_TYPE_X509: u8 = 1;
pub static DEFAULT_CAPABILITIES_EXT: Lazy<ext::CapabilitiesExt> =
    Lazy::new(|| ext::CapabilitiesExt {
        versions: vec![PROTOCOL_VERSION_MLS10],
        ciphersuites: vec![DefaultCipherSuite::tag()],
        extensions: vec![
            ExtensionType::Capabilities,
            ExtensionType::LifeTime,
            ExtensionType::KeyID,
            ExtensionType::ParentHash,
        ],
    });

/// spec: draft-ietf-mls-protocol.md#key-packages
#[derive(Clone)]
pub struct KeyPackagePayload<CS: CipherSuite> {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuiteTag,
    pub init_key: HPKEPublicKey<CS>,
    pub credential: Credential,
    pub extensions: Vec<ext::ExtensionEntry>,
}

impl<CS: CipherSuite> Debug for KeyPackagePayload<CS> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("KeyPackagePayload")
            .field("version", &self.version)
            .field("cipher_suite", &self.cipher_suite)
            .field("init_key", &self.init_key)
            .field("credential", &self.credential)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl<CS: CipherSuite> Codec for KeyPackagePayload<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.version.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.init_key.encode(bytes);
        self.credential.encode(bytes);
        utils::encode_vec_u32(bytes, &self.extensions);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let version = ProtocolVersion::read(r)?;
        let cipher_suite = CipherSuiteTag::read(r)?;
        let init_key = HPKEPublicKey::read(r)?;
        let credential = Credential::read(r)?;
        let extensions = utils::read_vec_u32(r)?;
        Some(Self {
            version,
            cipher_suite,
            init_key,
            credential,
            extensions,
        })
    }
}

impl<CS: CipherSuite> KeyPackagePayload<CS> {
    pub fn find_extension<T: MLSExtension>(&self) -> Result<T, FindExtensionError> {
        find_extension(&self.extensions)
    }

    /// insert or update extension
    pub fn put_extension<T: MLSExtension>(&mut self, ext: &T) {
        if let Some(found) = self
            .extensions
            .iter_mut()
            .find(|e| e.etype == T::EXTENSION_TYPE)
        {
            found.data = ext.get_encoding();
        } else {
            self.extensions.push(ext.entry());
        }
    }

    /// Verify key package payload
    pub fn verify(
        &self,
        ra_verifier: &impl AttestedCertVerifier,
        now: Timespec,
    ) -> Result<CertVerifyResult, Error> {
        if self.cipher_suite != CS::tag() {
            return Err(Error::UnsupportedCipherSuite(self.cipher_suite));
        }

        // Check for required extensions
        let capabilities = self.find_extension::<ext::CapabilitiesExt>()?;
        if !capabilities.versions.contains(&PROTOCOL_VERSION_MLS10) {
            return Err(Error::InvalidSupportedVersions);
        }
        if !capabilities.ciphersuites.contains(&self.cipher_suite) {
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

pub(crate) fn find_extension<T: MLSExtension>(
    extensions: &[ext::ExtensionEntry],
) -> Result<T, FindExtensionError> {
    let entry = extensions
        .iter()
        .find(|entry| entry.etype == T::EXTENSION_TYPE)
        .ok_or(FindExtensionError(T::EXTENSION_TYPE, "extension not found"))?;
    // FIXME check remaining data, need support from Codec trait
    <T>::read_bytes(&entry.data).ok_or(FindExtensionError(
        T::EXTENSION_TYPE,
        "extension decoding fails",
    ))
}

/// Key package, only send `(payload, signature)` to other nodes.
/// spec: draft-ietf-mls-protocol.md#key-packages
#[derive(Clone)]
pub struct KeyPackage<CS: CipherSuite> {
    pub payload: KeyPackagePayload<CS>,
    pub signature: Vec<u8>,
}

impl<CS: CipherSuite> Ord for KeyPackage<CS> {
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

impl<CS: CipherSuite> PartialOrd for KeyPackage<CS> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<CS: CipherSuite> PartialEq for KeyPackage<CS> {
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

impl<CS: CipherSuite> Eq for KeyPackage<CS> {}

impl<CS: CipherSuite> Debug for KeyPackage<CS> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("KeyPackage")
            .field("payload", &self.payload)
            .field("signature", &self.signature)
            .finish()
    }
}
impl<CS: CipherSuite> Codec for KeyPackage<CS> {
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

impl<CS: CipherSuite> KeyPackage<CS> {
    /// Verify key package and signature
    pub fn verify(
        &self,
        ra_verifier: &impl AttestedCertVerifier,
        now: Timespec,
    ) -> Result<CertVerifyResult, Error> {
        let info = self.payload.verify(ra_verifier, now)?;
        let public_key = IdentityPublicKey::new_unsafe(info.public_key.to_vec());
        public_key
            .verify_signature(&self.payload.get_encoding(), &self.signature)
            .map_err(Error::SignatureVerifyError)?;
        Ok(info)
    }

    /// re-sign payload
    pub fn update_signature(
        &mut self,
        private_key: &IdentityPrivateKey,
    ) -> Result<(), ring::error::Unspecified> {
        self.signature = private_key.sign(&self.payload.get_encoding())?;
        Ok(())
    }

    /// re-generate init key
    pub fn update_init_key(&mut self) -> Secret<SecretValue<CS>> {
        let leaf_secret = Secret::new(GenericSecret::gen());
        let (_, hpke_public) = derive_keypair(leaf_secret.expose_secret());
        self.payload.init_key = hpke_public;
        leaf_secret
    }
}

pub struct KeyPackageSecret<CS: CipherSuite> {
    pub credential_private_key: IdentityPrivateKey,
    pub leaf_secret: Secret<SecretValue<CS>>,
}

impl<CS: CipherSuite> KeyPackageSecret<CS> {
    pub fn init_private_key(&self) -> HPKEPrivateKey<CS> {
        derive_keypair(self.leaf_secret.expose_secret()).0
    }

    pub fn path_secret(&self) -> Secret<SecretValue<CS>> {
        CS::derive_secret(self.leaf_secret.expose_secret(), "path")
    }
}

#[cfg(target_env = "sgx")]
#[derive(thiserror::Error, Debug)]
pub enum GenKeyPackageError {
    #[error("ra context error: {0}")]
    RaContextError(#[from] EnclaveRaContextError),
    #[error("sign error: {0}")]
    SignError(#[from] ring::error::Unspecified),
    #[error("generated invalid certificate: {0}")]
    InvalidCertificate(#[from] nom::Err<X509Error>),
    #[error("generated invalid certificate private key: {0}")]
    InvalidPrivateKey(#[from] ring::error::KeyRejected),
}

impl<CS: CipherSuite> KeyPackageSecret<CS> {
    #[cfg(target_env = "sgx")]
    pub fn gen(ra_ctx: EnclaveRaContext) -> Result<(Self, KeyPackage<CS>), GenKeyPackageError> {
        let Certificate {
            certificate,
            private_key,
            ..
        } = ra_ctx.get_certificate()?;

        let (_, cert) = parse_x509_der(&certificate.0)?;
        let x509::Validity {
            not_before,
            not_after,
        } = &cert.tbs_certificate.validity;

        let extensions = vec![
            DEFAULT_CAPABILITIES_EXT.entry(),
            ext::LifeTimeExt::new(
                not_before.timestamp().try_into().unwrap(),
                not_after.timestamp().try_into().unwrap(),
            )
            .entry(),
        ];

        let credential_private_key = IdentityPrivateKey::from_pkcs8(&private_key.0)?;
        let leaf_secret = Secret::new(GenericSecret::gen());
        let (_, init_key) = derive_keypair(leaf_secret.expose_secret());
        let payload = KeyPackagePayload {
            version: PROTOCOL_VERSION_MLS10,
            cipher_suite: CS::tag(),
            init_key,
            credential: Credential::X509(certificate.0),
            extensions,
        };

        // sign payload
        let signature = credential_private_key.sign(&payload.get_encoding())?;

        Ok((
            Self {
                credential_private_key,
                leaf_secret,
            },
            KeyPackage { payload, signature },
        ))
    }

    /// re-sign payload
    pub fn update_signature(
        &self,
        keypackage: &mut KeyPackage<CS>,
    ) -> Result<(), ring::error::Unspecified> {
        keypackage.update_signature(&self.credential_private_key)
    }

    /// re-generate init key
    pub fn update_init_key(&mut self, keypackage: &mut KeyPackage<CS>) {
        self.leaf_secret = keypackage.update_init_key();
    }

    /// Verify key package secret and keypackage
    pub fn verify(
        &self,
        kp: &KeyPackage<CS>,
        ra_verifier: &impl AttestedCertVerifier,
        now: Timespec,
    ) -> Result<CertVerifyResult, Error> {
        verify_keypackage_and_secrets(
            kp,
            self.leaf_secret.expose_secret(),
            &self.credential_private_key,
            ra_verifier,
            now,
        )
    }
}

/// Verify key package secret and keypackage
pub fn verify_keypackage_and_secrets<CS: CipherSuite>(
    kp: &KeyPackage<CS>,
    leaf_secret: &SecretValue<CS>,
    credential_private_key: &IdentityPrivateKey,
    ra_verifier: &impl AttestedCertVerifier,
    now: Timespec,
) -> Result<CertVerifyResult, Error> {
    let info = kp.verify(ra_verifier, now)?;
    let (_, public_key) = derive_keypair::<CS>(leaf_secret);
    // verify init public key and private key match
    if !bool::from(kp.payload.init_key.marshal().ct_eq(&public_key.marshal())) {
        return Err(Error::KeypackageSecretDontMatch);
    }
    // verify signature public key and private key match
    if !bool::from(
        info.public_key
            .ct_eq(credential_private_key.public_key_raw()),
    ) {
        return Err(Error::KeypackageSecretDontMatch);
    }
    Ok(info)
}
