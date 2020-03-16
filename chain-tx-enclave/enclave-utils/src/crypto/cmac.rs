// 128-bit AES-CMAC
use aes::Aes128;
use cmac::{Cmac as InnerCmac, Mac};
use thiserror::Error;

const MAC_LEN: usize = 16;

pub type MacTag = [u8; MAC_LEN];

#[derive(Debug, Error)]
pub enum CmacError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("MAC error: {0}")]
    MacError(#[from] crypto_mac::MacError),
}

pub struct Cmac {
    key: [u8; MAC_LEN],
}

impl Cmac {
    pub fn new(key: &[u8; MAC_LEN]) -> Self {
        Self { key: *key }
    }

    pub fn sign(&self, data: &[u8]) -> Result<MacTag, CmacError> {
        let mut inner = InnerCmac::<Aes128>::new_varkey(&self.key[..])
            .map_err(|_| CmacError::InvalidKeyLength)?;
        inner.input(data);
        let mac = inner.result_reset();
        Ok(mac.code().into())
    }

    pub fn verify(&self, data: &[u8], tag: &MacTag) -> Result<(), CmacError> {
        let mut inner = InnerCmac::<Aes128>::new_varkey(&self.key[..])
            .map_err(|_| CmacError::InvalidKeyLength)?;
        inner.input(data);
        inner.verify(&tag[..]).map_err(Into::into)
    }
}
