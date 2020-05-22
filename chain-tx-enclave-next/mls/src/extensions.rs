use rustls::internal::msgs::codec::{self, Codec, Reader};
use std::convert::{TryFrom, TryInto};

use crate::keypackage::{CipherSuite, ProtocolVersion, Timespec};

/// spec: draft-ietf-mls-protocol.md#key-packages
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ExtensionType {
    Invalid = 0,
    SupportedVersions = 1,
    SupportedCipherSuites = 2,
    LifeTime = 3,
    KeyID = 4,
    ParentHash = 5,
}

impl TryFrom<u16> for ExtensionType {
    type Error = ();
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == ExtensionType::Invalid as u16 => Ok(ExtensionType::Invalid),
            x if x == ExtensionType::SupportedVersions as u16 => {
                Ok(ExtensionType::SupportedVersions)
            }
            x if x == ExtensionType::SupportedCipherSuites as u16 => {
                Ok(ExtensionType::SupportedCipherSuites)
            }
            x if x == ExtensionType::LifeTime as u16 => Ok(ExtensionType::LifeTime),
            x if x == ExtensionType::KeyID as u16 => Ok(ExtensionType::KeyID),
            x if x == ExtensionType::ParentHash as u16 => Ok(ExtensionType::ParentHash),
            _ => Err(()),
        }
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

/// spec: draft-ietf-mls-protocol.md#supported-versions-and-supported-ciphersuites
#[derive(Debug)]
pub struct SupportedVersionsExt(pub Vec<ProtocolVersion>);

impl Codec for SupportedVersionsExt {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.0.len() <= 0xff);
        (self.0.len() as u8).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let len = u8::read(r)? as usize;
        r.take(len)
            .map(|slice| SupportedVersionsExt(slice.to_vec()))
    }
}

impl MLSExtension for SupportedVersionsExt {
    const EXTENSION_TYPE: ExtensionType = ExtensionType::SupportedVersions;
}

/// spec: draft-ietf-mls-protocol.md#supported-versions-and-supported-ciphersuites
#[derive(Debug, PartialEq)]
pub struct SupportedCipherSuitesExt(pub Vec<CipherSuite>);
impl Codec for SupportedCipherSuitesExt {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u8(bytes, &self.0)
    }

    fn read(r: &mut Reader) -> Option<Self> {
        codec::read_vec_u8(r).map(Self)
    }
}
impl MLSExtension for SupportedCipherSuitesExt {
    const EXTENSION_TYPE: ExtensionType = ExtensionType::SupportedCipherSuites;
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
pub struct ParentHashExt(pub Vec<u8>);

impl Codec for ParentHashExt {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u8(bytes, &self.0);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        codec::read_vec_u8(r).map(Self)
    }
}

impl MLSExtension for ParentHashExt {
    const EXTENSION_TYPE: ExtensionType = ExtensionType::ParentHash;
}

/// Extension entry included in `KeyPackage`
#[derive(Debug)]
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
