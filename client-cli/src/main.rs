#![deny(missing_docs, unsafe_code, unstable_features)]
//! CLI for interacting with Crypto.com Chain
mod command;

use failure::ResultExt;
use quest::{ask, error, password};
use secstr::SecUtf8;
use structopt::StructOpt;

use client_common::{ErrorKind, Result};

use crate::command::Command;

fn main() {
    if let Err(err) = execute() {
        match std::env::var("CRYPTO_CLIENT_DEBUG") {
            Ok(debug) => {
                if "true" == debug {
                    error(&format!("Error: {:?}", err))
                } else {
                    error(&format!("Error: {}", err))
                }
            }
            Err(_) => error(&format!("Error: {}", err)),
        }

        std::process::exit(1);
    }
}

fn execute() -> Result<()> {
    let command = Command::from_args();
    command.execute()
}

pub(crate) fn storage_path() -> String {
    match std::env::var("CRYPTO_CLIENT_STORAGE") {
        Ok(path) => path,
        Err(_) => ".storage".to_owned(),
    }
}

pub(crate) fn tendermint_url() -> String {
    match std::env::var("CRYPTO_CLIENT_TENDERMINT") {
        Ok(url) => url,
        Err(_) => "http://localhost:26657/".to_owned(),
    }
}

pub(crate) fn ask_passphrase(message: Option<&str>) -> Result<SecUtf8> {
    match message {
        None => ask("Enter passphrase: "),
        Some(message) => ask(message),
    }
    Ok(password().context(ErrorKind::IoError)?.into())
}
