use parity_scale_codec::{Decode, Encode};
use rand::{rngs::OsRng, Rng};
use sgx_types::*;
use std::env;

const XOR_KEY: u8 = 0xAB;

#[derive(PartialEq)]
pub struct UnsealedData {
    additional: Vec<u8>,
    data: Vec<u8>,
}

impl UnsealedData {
    pub fn get_decrypt_txt(&self) -> &[u8] {
        &self.data
    }
    pub fn get_additional_txt(&self) -> &[u8] {
        &self.additional
    }
    pub fn clear(&mut self) {}
}

#[derive(Encode, Decode, Debug, PartialEq)]
pub struct SealedData {
    additional: Vec<u8>,
    data: Vec<u8>,
}

fn xor_byte(b: u8) -> u8 {
    b ^ XOR_KEY
}

impl SealedData {
    pub fn from_bytes(input: &mut [u8]) -> Option<Self> {
        Self::decode(&mut &*input).ok()
    }

    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        Some(self.encode())
    }

    pub fn unseal_data(&self) -> SgxResult<UnsealedData> {
        Ok(UnsealedData {
            data: self.data.iter().copied().map(xor_byte).collect(),
            additional: self.additional.iter().copied().map(xor_byte).collect(),
        })
    }

    pub fn seal_data(additional: &[u8], data: &[u8]) -> SgxResult<Self> {
        Ok(SealedData {
            additional: additional.iter().copied().map(xor_byte).collect(),
            data: data.iter().copied().map(xor_byte).collect(),
        })
    }
}

pub fn os_rng_fill(output: &mut [u8]) {
    OsRng.fill(output)
}

lazy_static! {
    pub static ref NETWORK_HEX_ID: u8 = env::var("NETWORK_ID").unwrap().parse().unwrap();
    pub static ref MOCK_KEY: [u8; 16] = [0u8; 16];
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

    quickcheck! {
        fn seal_unseal_symetric(additional: Vec<u8>, data: Vec<u8>) -> bool {
            let sealed = SealedData::seal_data(&additional, &data).unwrap();
            let mut encoded = sealed.to_bytes().unwrap();
            let decoded = SealedData::from_bytes(&mut encoded).unwrap();
            assert_eq!(&sealed, &decoded);
            decoded.unseal_data().unwrap() == UnsealedData{additional, data}
        }
    }
}
