//! gen keypackage in the client
use std::convert::TryInto;
use std::process;

use chain_core::common::Timespec;
use chrono::offset::Utc;
use mls::{Codec, KeyPackage};
use ra_client::ENCLAVE_CERT_VERIFIER;

use crate::{Error, ErrorKind, Result, ResultExt};

/// gen keypackage by running mls enclave
pub fn gen_keypackage(sgxs_path: &str) -> Result<Vec<u8>> {
    let output = process::Command::new("ftxsgx-runner")
        .arg(sgxs_path)
        .arg("--signature")
        .arg("coresident")
        .output()
        .map_err(|err| Error::new(ErrorKind::RunEnclaveError, err.to_string()))?;
    if !output.status.success() {
        return Err(Error::new(
            ErrorKind::RunEnclaveError,
            format!(
                "enclave runner return error code: {:?}, stderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
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
    let keypackage = KeyPackage::read_bytes(keypackage)
        .err_kind(ErrorKind::InvalidInput, || "keypackage decode fail")?;
    keypackage
        .verify(ENCLAVE_CERT_VERIFIER.clone(), now)
        .err_kind(ErrorKind::InvalidInput, || "keypackage verify fail")?;
    Ok(())
}
