#[cfg(target_env = "sgx")]
use std::io::{self, Write};
pub type Timespec = u64;

#[cfg(target_env = "sgx")]
fn main() -> io::Result<()> {
    use mls::{DefaultCipherSuite, KeyPackageSecret};
    use ra_enclave::{EnclaveRaConfig, EnclaveRaContext, DEFAULT_EXPIRATION_SECS};
    #[allow(unused_imports)]
    use rs_libc::alloc::*;
    use rustls::internal::msgs::codec::Codec;

    let config = EnclaveRaContext::new(&EnclaveRaConfig {
        sp_addr: "0.0.0.0:8989".to_owned(),
        certificate_validity_secs: DEFAULT_EXPIRATION_SECS as u32,
        certificate_expiration_time: None,
    });
    if config.is_err() {
        eprintln!("cannot connect ra-sp-server, run ra-sp-server beforehand e.g.) ra-sp-server --quote-type Unlinkable --ias-key $IAS_API_KEY --spid $SPID")
    }
    let (_, keypackage) = KeyPackageSecret::<DefaultCipherSuite>::gen(config.unwrap()).unwrap();

    let now = chrono::Utc::now().timestamp() as u64;
    let verication_result = keypackage.verify(&*ra_client::ENCLAVE_CERT_VERIFIER, now);
    if let Err(value) = verication_result {
        eprintln!("verification_fail {}", value);
        io::stdout().write_all("-1".as_bytes())
    } else {
        io::stdout().write_all(&keypackage.get_encoding())
    }
}

#[cfg(not(target_env = "sgx"))]
fn main() {
    eprintln!("Please enable edp feature and run in edp environemnt");
}
