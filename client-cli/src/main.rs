#![deny(missing_docs, unsafe_code, unstable_features)]
//! CLI for interacting with Crypto.com Chain
mod command;

use quest::{ask, error, password};
use secstr::SecUtf8;
use structopt::StructOpt;

use client_common::{ErrorKind, Result, ResultExt};

use crate::command::Command;

fn main() {
    if let Err(err) = execute() {
        match std::env::var("CRYPTO_CLIENT_PROD") {
            Ok(prod) => {
                if "true" == prod {
                    error(&format!("Error: {}", err))
                } else {
                    error(&format!("Error: {:?}", err))
                }
            }
            Err(_) => error(&format!("Error: {:?}", err)),
        }

        std::process::exit(1);
    }
}

#[inline]
fn execute() -> Result<()> {
    let command = Command::from_args();
    command.execute()
}

#[inline]
pub(crate) fn storage_path() -> String {
    std::env::var("CRYPTO_CLIENT_STORAGE").unwrap_or_else(|_| ".storage".to_owned())
}

#[inline]
pub(crate) fn tendermint_url() -> String {
    std::env::var("CRYPTO_CLIENT_TENDERMINT")
        .unwrap_or_else(|_| "http://localhost:26657/".to_owned())
}

#[inline]
pub(crate) fn ask_passphrase(message: Option<&str>) -> Result<SecUtf8> {
    ask(message.unwrap_or("Enter passphrase: "));
    password()
        .map(Into::into)
        .chain(|| (ErrorKind::IoError, "Unable to read password"))
}
