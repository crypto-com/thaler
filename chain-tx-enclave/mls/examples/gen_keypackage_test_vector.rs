#[cfg(target_env = "sgx")]
use std::io::{self, Write};

#[cfg(target_env = "sgx")]
fn main() -> io::Result<()> {
    use mls::OwnedKeyPackage;
    use ra_enclave::{EnclaveRaConfig, EnclaveRaContext};
    #[allow(unused_imports)]
    use rs_libc::alloc::*;
    use rustls::internal::msgs::codec::Codec;

    let kp = OwnedKeyPackage::new(
        EnclaveRaContext::new(&EnclaveRaConfig {
            sp_addr: "0.0.0.0:8989".to_owned(),
            certificate_validity_secs: 86400,
        })
        .unwrap(),
    )
    .unwrap();
    io::stdout().write_all(&kp.keypackage.get_encoding())
}

#[cfg(not(target_env = "sgx"))]
fn main() {
    eprintln!("Please enable edp feature and run in edp environemnt");
}
