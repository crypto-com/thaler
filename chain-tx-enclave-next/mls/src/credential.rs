//! Credential in keypackage
use rustls::internal::msgs::codec::{Codec, Reader};

use crate::utils;

/// Don't support basic credential, only for parsing.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct BasicCredential {
    identity: Vec<u8>,
    public_key: Vec<u8>,
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
                1_u8.encode(bytes);
                utils::encode_vec_u8_u16(bytes, &v.identity);
                utils::encode_vec_u8_u16(bytes, &v.public_key);
            }
            Credential::X509(data) => {
                2_u8.encode(bytes);
                utils::encode_vec_u8_u24(bytes, data);
            }
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        match u8::read(r)? {
            1 => {
                let identity = utils::read_vec_u8_u16(r)?;
                let public_key = utils::read_vec_u8_u16(r)?;
                Some(Credential::Basic(BasicCredential {
                    identity,
                    public_key,
                }))
            }
            2 => utils::read_vec_u8_u24_limited(r, 0xff_ffff).map(Credential::X509),
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
