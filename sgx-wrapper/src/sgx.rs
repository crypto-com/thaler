use enclave_macro::{get_network_id, mock_key};
use sgx_rand::{os::SgxRng, Rng};
use sgx_tseal::{SgxSealedData, SgxUnsealedData};
use sgx_types::{sgx_sealed_data_t, SgxResult};
use std::prelude::v1::Vec;
use zeroize::Zeroize;

pub struct UnsealedData<'a>(SgxUnsealedData<'a, [u8]>);

impl<'a> UnsealedData<'a> {
    pub fn get_decrypt_txt(&self) -> &[u8] {
        self.0.get_decrypt_txt()
    }
    pub fn get_additional_txt(&self) -> &[u8] {
        self.0.get_additional_txt()
    }
    pub fn clear(&mut self) {
        self.0.decrypt.zeroize();
    }
}

pub struct SealedData<'a>(SgxSealedData<'a, [u8]>);

impl<'a> SealedData<'a> {
    pub fn from_bytes(input: &mut [u8]) -> Option<Self> {
        if input.len() >= (std::u32::MAX as usize) {
            return None;
        }
        let opt = unsafe {
            SgxSealedData::<[u8]>::from_raw_sealed_data_t(
                input.as_mut_ptr() as *mut sgx_sealed_data_t,
                input.len() as u32,
            )
        };
        opt.map(Self)
    }

    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let sealed_log_size = SgxSealedData::<[u8]>::calc_raw_sealed_data_size(
            self.0.get_add_mac_txt_len(),
            self.0.get_encrypt_txt_len(),
        ) as usize;
        let mut sealed_log: Vec<u8> = vec![0u8; sealed_log_size];

        unsafe {
            let sealed_r = self.0.to_raw_sealed_data_t(
                sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t,
                sealed_log_size as u32,
            );
            if sealed_r.is_none() {
                return None;
            }
        }

        Some(sealed_log)
    }

    pub fn unseal_data(&self) -> SgxResult<UnsealedData> {
        self.0.unseal_data().map(UnsealedData)
    }

    pub fn seal_data(additional: &[u8], data: &'a [u8]) -> SgxResult<Self> {
        SgxSealedData::<'a, [u8]>::seal_data(additional, data).map(Self)
    }
}

pub fn os_rng_fill(vector: &mut [u8]) {
    let mut os_rng = SgxRng::new().unwrap();
    os_rng.fill_bytes(vector);
}

lazy_static! {
    pub static ref NETWORK_HEX_ID: u8 = get_network_id!();
    pub static ref MOCK_KEY: [u8; 16] = mock_key!();
}
