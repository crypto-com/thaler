pub mod zmq_helper;

#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
use aead::{generic_array::GenericArray, Aead, NewAead};
#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
use aes_gcm::Aes128Gcm;
use aes_gcm::Tag;
#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
use rand::random;
use sgx_isa::Keyrequest;
#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
use sgx_isa::{ErrorCode, Keyname, Keypolicy, Report};
use std::convert::TryFrom;
#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
use zeroize::Zeroize;

/// Cryptographic payload in the sealed log of Intel SGX SDK
/// (tag is detached, unlike in RFC-5116)
pub struct AesGcmData {
    pub payload_tag: Tag,
    pub encrypt_txt: Vec<u8>,
    pub additional_txt: Vec<u8>,
}

/// Data contained in the sealed log payload from Intel SGX SDK
pub struct SealedData {
    pub key_request: Keyrequest,
    pub aes_data: AesGcmData,
}

/// current setup in tx-validation
/// FIXME: check, verify and adapt when tx-validation is moved to EDP + "production"
#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
const MISCMASK: u32 = 4026531840;
#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
const ATTRIBUTEMASK: [u64; 2] = [18374686479671623691, 0];

impl SealedData {
    #[cfg(all(feature = "sgxstd", target_env = "sgx"))]
    pub fn seal(plain: &[u8], txid: [u8; 32]) -> Result<Vec<u8>, ErrorCode> {
        let plain_len = plain.len();
        // TODO: max tx size instead of u32::MAX
        if plain_len + 32 > (u32::MAX as usize) {
            // TODO: better error code
            return Err(ErrorCode::Success);
        }
        let report = Report::for_self();
        const RESERVED: [u8; 12] = [0; 12];
        let plain_offset = plain_len as u32;
        let payload_len = plain_offset + 32;
        // in Intel SDK, keys are unique per request; nonce is 0
        // https://github.com/intel/linux-sgx/blob/master/sdk/tseal/tSeal_internal.cpp#L123
        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let mut encrypt_txt = plain.to_vec();
        let mut result =
            Vec::with_capacity(plain_len + Keyrequest::UNPADDED_SIZE + 4 * 2 + 12 * 2 + 16 + 32);
        let key_request = Keyrequest {
            keyname: Keyname::Seal as _,
            keypolicy: Keypolicy::MRSIGNER,
            isvsvn: report.isvsvn,
            cpusvn: report.cpusvn,
            attributemask: ATTRIBUTEMASK,
            keyid: random(), // random in Intel SDK
            miscmask: MISCMASK,
            ..Default::default()
        };
        result.extend_from_slice(key_request.as_ref());
        result.extend_from_slice(&u32::to_le_bytes(plain_offset)[..]);
        result.extend_from_slice(&RESERVED[..]);
        result.extend_from_slice(&u32::to_le_bytes(payload_len)[..]);
        result.extend_from_slice(&RESERVED[..]);

        let mut key = key_request.egetkey()?;
        let gk = GenericArray::clone_from_slice(&key);
        key.zeroize();
        let aead = Aes128Gcm::new(gk);
        if let Ok(tag) = aead.encrypt_in_place_detached(nonce, &txid, &mut encrypt_txt) {
            result.extend_from_slice(&tag);
            result.extend_from_slice(&encrypt_txt);
            result.extend_from_slice(&txid);
            Ok(result)
        } else {
            // WARNING / FIXME in new version of aes-gcm: https://github.com/RustCrypto/AEADs/issues/65
            Err(ErrorCode::MacCompareFail)
        }
    }

    pub fn try_copy_from(source: &[u8]) -> Option<Self> {
        let mut pos: usize = 0;
        let mut take = |n: usize| -> Option<&[u8]> {
            if n > 0 && source.len() >= pos + n {
                let ret = &source[pos..pos + n];
                pos += n;
                Some(ret)
            } else {
                None
            }
        };
        let key_request = Keyrequest::try_copy_from(take(Keyrequest::UNPADDED_SIZE)?)?;
        let plain_text_offset = u32::from_le_bytes(
            <[u8; 4]>::try_from(take(4)?).expect("should be slice with 4 bytes"),
        ) as usize;
        let _reserved = take(12)?;
        let payload_size = u32::from_le_bytes(
            <[u8; 4]>::try_from(take(4)?).expect("should be slice with 4 bytes"),
        );
        let _reserved = take(12)?;
        let payload_tag = Tag::clone_from_slice(take(16)?);
        let payload = take(payload_size as usize)?;
        let encrypt_txt = payload.get(0..plain_text_offset)?.to_vec();
        let additional_txt = payload.get(plain_text_offset..payload.len())?.to_vec();
        Some(Self {
            key_request,
            aes_data: AesGcmData {
                payload_tag,
                encrypt_txt,
                additional_txt,
            },
        })
    }

    #[cfg(all(feature = "sgxstd", target_env = "sgx"))]
    pub fn unseal(&self) -> Result<Vec<u8>, ErrorCode> {
        // Make sure the parameters that are not checked for correctness
        // by EGETKEY match the current enclave. Without this check,
        // EGETKEY will proceed to derive a key, which will be an
        // incorrect key.
        if ATTRIBUTEMASK != self.key_request.attributemask || MISCMASK != self.key_request.miscmask
        {
            return Err(ErrorCode::InvalidAttribute);
        }
        // in Intel SDK, keys are unique per request; nonce is 0
        // https://github.com/intel/linux-sgx/blob/master/sdk/tseal/tSeal_internal.cpp#L123
        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let mut result = self.aes_data.encrypt_txt.clone();
        let mut key = self.key_request.egetkey()?;
        let gk = GenericArray::clone_from_slice(&key);
        key.zeroize();
        let aead = Aes128Gcm::new(gk);
        if aead
            .decrypt_in_place_detached(
                nonce,
                &self.aes_data.additional_txt,
                &mut result,
                &self.aes_data.payload_tag,
            )
            .is_ok()
        {
            Ok(result)
        } else {
            // WARNING / FIXME in new version of aes-gcm: https://github.com/RustCrypto/AEADs/issues/65
            Err(ErrorCode::MacCompareFail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // can be run with cargo test --target x86_64-fortanix-unknown-sgx --features sgxstd
    #[cfg(all(feature = "sgxstd", target_env = "sgx"))]
    #[test]
    fn seal_unseal() {
        let v: [u8; 32] = random();
        let id: [u8; 32] = random();
        let sealed = SealedData::seal(&v[..], id).expect("sealed");
        assert_eq!(
            SealedData::try_copy_from(&sealed)
                .expect("parsed")
                .unseal()
                .expect("unsealed"),
            v
        );
    }

    #[test]
    fn test_parse() {
        // example sealed log from simulation mode
        let sealed_log: [u8; 688] = [
            4, 0, 2, 0, 0, 0, 0, 0, 72, 32, 243, 55, 106, 230, 178, 242, 3, 77, 59, 122, 75, 72,
            167, 120, 11, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 159, 90, 185, 136, 151,
            148, 228, 36, 92, 194, 38, 35, 136, 235, 6, 236, 251, 134, 157, 248, 243, 13, 150, 160,
            220, 173, 255, 89, 57, 80, 66, 44, 0, 0, 0, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 115, 137, 179, 186, 59,
            128, 199, 133, 59, 252, 248, 251, 92, 67, 55, 65, 230, 26, 151, 192, 73, 209, 101, 137,
            255, 239, 235, 59, 153, 226, 219, 100, 136, 67, 68, 79, 82, 143, 183, 154, 20, 158, 44,
            138, 197, 120, 223, 47, 37, 213, 93, 224, 137, 76, 160, 51, 109, 125, 175, 44, 224,
            227, 180, 238, 158, 43, 107, 129, 239, 95, 63, 215, 190, 222, 8, 123, 159, 66, 113, 66,
            158, 58, 115, 90, 29, 219, 225, 136, 244, 228, 186, 161, 221, 15, 80, 58, 134, 246,
            215, 7, 153, 174, 21, 139, 238, 161, 201, 9, 175, 3, 226, 184, 195, 177, 45, 10, 170,
            182, 128, 179, 239, 167, 155, 41, 100, 1, 177, 113, 192, 221, 178, 38, 181, 46, 69,
            253, 219, 208, 134, 252, 105, 177, 176, 139,
        ];
        SealedData::try_copy_from(&sealed_log).expect("parses");
    }
}
