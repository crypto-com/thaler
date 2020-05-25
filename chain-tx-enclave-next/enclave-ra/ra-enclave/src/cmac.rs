// 128-bit AES-CMAC
use aes::Aes128;
use cmac::{Cmac as InnerCmac, Mac};
use thiserror::Error;

const MAC_LEN: usize = 16;

pub type MacCode = [u8; MAC_LEN];

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
    /// Creates a new CMAC from given key
    pub fn new(key: &[u8; MAC_LEN]) -> Self {
        Self { key: *key }
    }

    /// Checks if the code is correct for data
    pub fn verify(&self, data: &[u8], code: &MacCode) -> Result<(), CmacError> {
        let mut inner = InnerCmac::<Aes128>::new_varkey(&self.key[..])
            .map_err(|_| CmacError::InvalidKeyLength)?;
        inner.input(data);
        inner.verify(&code[..]).map_err(Into::into)
    }
}
