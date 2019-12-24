#[cfg(feature = "mesalock_sgx")]
pub mod enclave_u;

pub fn storage_path() -> String {
    match std::env::var("TX_ENCLAVE_STORAGE") {
        Ok(path) => path,
        Err(_) => ".enclave".to_owned(),
    }
}

pub const META_KEYSPACE: &[u8] = b"meta";
pub const TX_KEYSPACE: &[u8] = b"tx";
