use rustls::internal::msgs::codec::{self, Codec, Reader};
use std::convert::{TryFrom, TryInto};

use crate::ciphersuite::{CipherSuite, CipherSuiteTag, HashValue};
use crate::keypackage::{ProtocolVersion, Timespec};
use crate::utils;

/// spec: draft-ietf-mls-protocol.md#key-packages
#[repr(u16)]
#[derive(Debug, PartialEq, Copy, Clone, Ord, PartialOrd, Eq)]
pub enum ExtensionType {
    Invalid = 0,
    Capabilities = 1,
    LifeTime = 2,
    KeyID = 3,
    ParentHash = 4,
    RatchetTree = 5,
}

impl TryFrom<u16> for ExtensionType {
    type Error = ();
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == ExtensionType::Invalid as u16 => Ok(ExtensionType::Invalid),
            x if x == ExtensionType::Capabilities as u16 => Ok(ExtensionType::Capabilities),
            x if x == ExtensionType::LifeTime as u16 => Ok(ExtensionType::LifeTime),
            x if x == ExtensionType::KeyID as u16 => Ok(ExtensionType::KeyID),
            x if x == ExtensionType::ParentHash as u16 => Ok(ExtensionType::ParentHash),
            x if x == ExtensionType::RatchetTree as u16 => Ok(ExtensionType::RatchetTree),
            _ => Err(()),
        }
    }
}

impl Codec for ExtensionType {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u16).encode(bytes)
    }
    fn read(r: &mut Reader) -> Option<Self> {
        u16::read(r).map(|n| Self::try_from(n).ok()).flatten()
    }
}

/// Extendable extension trait
pub trait MLSExtension: Codec {
    const EXTENSION_TYPE: ExtensionType;
    fn entry(&self) -> ExtensionEntry {
        ExtensionEntry {
            etype: Self::EXTENSION_TYPE,
            data: self.get_encoding(),
        }
    }
}

/// spec: draft-ietf-mls-protocol.md#client-capabilities
#[derive(Debug)]
pub struct CapabilitiesExt {
    pub versions: Vec<ProtocolVersion>,
    pub ciphersuites: Vec<CipherSuiteTag>,
    pub extensions: Vec<ExtensionType>,
}

impl Codec for CapabilitiesExt {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u8(bytes, &self.versions);
        codec::encode_vec_u8(bytes, &self.ciphersuites);
        codec::encode_vec_u8(bytes, &self.extensions);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let versions = codec::read_vec_u8(r)?;
        let ciphersuites = codec::read_vec_u8(r)?;
        let extensions = codec::read_vec_u8(r)?;
        Some(Self {
            versions,
            ciphersuites,
            extensions,
        })
    }
}

impl MLSExtension for CapabilitiesExt {
    const EXTENSION_TYPE: ExtensionType = ExtensionType::Capabilities;
}

/// spec: draft-ietf-mls-protocol.md#lifetime
#[derive(Debug)]
pub struct LifeTimeExt {
    pub not_before: Timespec,
    pub not_after: Timespec,
}

impl LifeTimeExt {
    pub fn new(not_before: Timespec, not_after: Timespec) -> Self {
        Self {
            not_before,
            not_after,
        }
    }
}

impl Codec for LifeTimeExt {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.not_before.encode(bytes);
        self.not_after.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let not_before = Timespec::read(r)?;
        let not_after = Timespec::read(r)?;
        Some(Self {
            not_before,
            not_after,
        })
    }
}

impl MLSExtension for LifeTimeExt {
    const EXTENSION_TYPE: ExtensionType = ExtensionType::LifeTime;
}

/// spec: draft-ietf-mls-protocol.md#keypackage-identifiers
#[derive(Debug)]
pub struct KeyIDExt(pub Vec<u8>);

impl Codec for KeyIDExt {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u16(bytes, &self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        codec::read_vec_u16(r).map(Self)
    }
}

impl MLSExtension for KeyIDExt {
    const EXTENSION_TYPE: ExtensionType = ExtensionType::KeyID;
}

/// spec: draft-ietf-mls-protocol.md#parent-hash
#[derive(Debug)]
pub struct ParentHashExt<CS: CipherSuite>(pub Option<HashValue<CS>>);

impl<CS: CipherSuite> Codec for ParentHashExt<CS> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        utils::encode_vec_u8_u8(bytes, self.0.as_ref().map_or(&[], |h| h.as_ref()));
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let v = utils::read_vec_u8_u8(r)?;
        let hash = if v.is_empty() {
            None
        } else {
            Some(HashValue::try_from(v.as_slice()).ok()?)
        };
        Some(Self(hash))
    }
}

impl<CS: CipherSuite> MLSExtension for ParentHashExt<CS> {
    const EXTENSION_TYPE: ExtensionType = ExtensionType::ParentHash;
}

/// Extension entry included in `KeyPackage`
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct ExtensionEntry {
    pub etype: ExtensionType,
    pub data: Vec<u8>,
}

impl Codec for ExtensionEntry {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.etype as u16).encode(bytes);
        codec::encode_vec_u16(bytes, &self.data);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let etype = u16::read(r)?.try_into().ok()?;
        let data = codec::read_vec_u16(r)?;
        Some(Self { etype, data })
    }
}
