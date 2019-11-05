#![deny(missing_docs, unsafe_code, unstable_features)]
//! CLI for interacting with Crypto.com Chain
mod command;
#[allow(unused_imports)]
use quest::{ask, error, password};
use secstr::SecUtf8;
use structopt::StructOpt;

use std::str::FromStr;

use chain_core::init::{coin::Coin, network::init_chain_id};
use client_common::{Error, ErrorKind, Result, ResultExt};

use crate::command::Command;

fn main() {
    env_logger::init();
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

#[inline]
fn execute() -> Result<()> {
    if let Some(chain_id) = chain_id() {
        init_chain_id(&chain_id);
    } else {
        ask("Warning! `CRYPTO_CHAIN_ID` environment variable is not set. Setting network to devnet and network-id to 0");
        println!();
    }

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
        .unwrap_or_else(|_| "ws://localhost:26657/websocket".to_owned())
}

#[inline]
pub(crate) fn chain_id() -> Option<String> {
    std::env::var("CRYPTO_CHAIN_ID").map(Some).unwrap_or(None)
}

#[cfg(not(test))]
pub(crate) fn ask_passphrase(message: Option<&str>) -> Result<SecUtf8> {
    ask(message.unwrap_or("Enter passphrase: "));
    password()
        .map(Into::into)
        .chain(|| (ErrorKind::IoError, "Unable to read password"))
}

#[cfg(test)]
pub(crate) fn ask_passphrase(_message: Option<&str>) -> Result<SecUtf8> {
    Ok(SecUtf8::from("123456"))
}

pub(crate) fn coin_from_str(coin_str: &str) -> Result<Coin> {
    if !coin_str.contains('.') {
        Coin::from_str(&format!("{}00000000", coin_str)).chain(|| {
            (
                ErrorKind::DeserializationError,
                format!("Unable to deserialize coin from value: {}", coin_str),
            )
        })
    } else {
        let coin_parts = coin_str.split('.').collect::<Vec<&str>>();

        if 2 != coin_parts.len() {
            return Err(Error::new(
                ErrorKind::DeserializationError,
                format!("Too many decimal points in coin: {}", coin_str),
            ));
        }

        let mut iter = coin_parts.iter();

        let before_decimal = iter.next().unwrap();
        let after_decimal = iter.next().unwrap();

        if after_decimal.len() > 8 {
            return Err(Error::new(
                ErrorKind::DeserializationError,
                format!("Too many digits after decimal in coin: {}", coin_str),
            ));
        }

        Coin::from_str(&format!("{}{:0<8}", before_decimal, after_decimal)).chain(|| {
            (
                ErrorKind::DeserializationError,
                format!("Unable to deserialize coin from value: {}", coin_str),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_coin_from_str() {
        assert_eq!(Coin::new(100000000).unwrap(), coin_from_str("1").unwrap());

        assert_eq!(
            Coin::new(100_000_000_000__0000_0000).unwrap(),
            coin_from_str("100000000000").unwrap()
        );

        assert_eq!(
            ErrorKind::DeserializationError,
            coin_from_str("100000000001").unwrap_err().kind()
        );

        assert_eq!(
            ErrorKind::DeserializationError,
            coin_from_str("10000.000000.1").unwrap_err().kind()
        );

        assert_eq!(
            ErrorKind::DeserializationError,
            coin_from_str("100.000000001").unwrap_err().kind()
        );

        assert_eq!(
            Coin::new(100000000001).unwrap(),
            coin_from_str("1000.00000001").unwrap()
        );

        assert_eq!(
            Coin::new(100_000_000_000__0000_0000).unwrap(),
            coin_from_str("100000000000.00000000").unwrap()
        );

        assert_eq!(
            ErrorKind::DeserializationError,
            coin_from_str("100000000000.00000001").unwrap_err().kind()
        );
    }
}
