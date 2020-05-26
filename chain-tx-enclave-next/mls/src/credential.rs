//! Credential in keypackage
use rustls::internal::msgs::codec::{Codec, Reader};

use crate::utils;

/// Don't support basic credential, only for parsing.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct BasicCredential {
    identity: Vec<u8>,
    sig_schema: u16,
    sig_pubkey: Vec<u8>,
}

/// Credential in keypackage
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Credential {
    /// don't support, only for parsing
    Basic(BasicCredential),
    /// Remote Attestation X509 certificate
    X509(Vec<u8>),
}

impl Codec for Credential {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Credential::Basic(v) => {
                0_u8.encode(bytes);
                utils::encode_vec_u8_u16(bytes, &v.identity);
                v.sig_schema.encode(bytes);
                utils::encode_vec_u8_u16(bytes, &v.sig_pubkey);
            }
            Credential::X509(data) => {
                1_u8.encode(bytes);
                utils::encode_vec_u8_u24(bytes, data);
            }
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        match u8::read(r)? {
            0 => {
                let identity = utils::read_vec_u8_u16(r)?;
                let sig_schema = u16::read(r)?;
                let sig_pubkey = utils::read_vec_u8_u16(r)?;
                Some(Credential::Basic(BasicCredential {
                    identity,
                    sig_schema,
                    sig_pubkey,
                }))
            }
            1 => utils::read_vec_u8_u24_limited(r, 0xff_ffff).map(Credential::X509),
            _ => None,
        }
    }
}

impl Credential {
    pub fn x509(&self) -> Option<&[u8]> {
        match self {
            Credential::X509(data) => Some(data),
            _ => None,
        }
    }
}
