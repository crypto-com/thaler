//! gen keypackage in the client
use std::convert::TryInto;
use std::process;

use chain_core::common::Timespec;
use chrono::offset::Utc;
use mls::{Codec, DefaultCipherSuite, KeyPackage};
use ra_client::ENCLAVE_CERT_VERIFIER;

use client_common::{Error, ErrorKind, Result, ResultExt};

/// gen keypackage by running mls enclave
pub fn gen_keypackage(sgxs_path: &str) -> Result<Vec<u8>> {
    let output = process::Command::new("ftxsgx-runner")
        .arg(sgxs_path)
        .arg("--signature")
        .arg("coresident")
        .output()
        .map_err(|err| Error::new(ErrorKind::RunEnclaveError, err.to_string()))?;
    if !output.status.success() {
        let check_ra_sp_server="run ra-sp-server beforehand  e.g.) ./ra-sp-server --quote-type Unlinkable --ias-key $IAS_API_KEY --spid $SPID";
        let check_mls =
            "check mls path is correct  e.g.) mls.sgxs, mls.sig  <- two files are necessary";
        return Err(Error::new(
            ErrorKind::RunEnclaveError,
            format!(
                "enclave runner return error code: {:?}, stderr: {}\n{}\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr),
                check_ra_sp_server,
                check_mls,
            ),
        ));
    }
    Ok(output.stdout)
}

/// verify serialized keypackage blob against current time
pub fn verify_keypackage(keypackage: &[u8]) -> Result<()> {
    let now: Timespec = Utc::now()
        .timestamp()
        .try_into()
        .expect("reversed time flow");
    let keypackage = KeyPackage::<DefaultCipherSuite>::read_bytes(keypackage)
        .err_kind(ErrorKind::InvalidInput, || "keypackage decode fail")?;
    keypackage
        .verify(&*ENCLAVE_CERT_VERIFIER, now)
        .err_kind(ErrorKind::InvalidInput, || "keypackage verify fail")?;
    Ok(())
}
