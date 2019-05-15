mod command;

use failure::ResultExt;
use quest::{ask, error, password};
use secstr::SecStr;
use structopt::StructOpt;

use client_common::storage::SledStorage;
use client_common::tendermint::{Client, RpcClient};
use client_common::{ErrorKind, Result};
use client_core::transaction_builder::DefaultTransactionBuilder;
use client_core::wallet::DefaultWalletClient;
use client_index::index::DefaultIndex;

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
    }
}

fn execute() -> Result<()> {
    let storage = SledStorage::new(storage_path())?;
    let tendermint_client = RpcClient::new(&tendermint_url());
    let transaction_builder =
        DefaultTransactionBuilder::new(tendermint_client.genesis()?.fee_policy());
    let transaction_index = DefaultIndex::new(storage.clone(), tendermint_client);

    let wallet_client = DefaultWalletClient::new(storage, transaction_index, transaction_builder);
    let command = Command::from_args();

    command.execute(wallet_client)
}

fn storage_path() -> String {
    match std::env::var("CRYPTO_CLIENT_STORAGE") {
        Ok(path) => path,
        Err(_) => ".storage".to_owned(),
    }
}

fn tendermint_url() -> String {
    match std::env::var("CRYPTO_CLIENT_TENDERMINT") {
        Ok(url) => url,
        Err(_) => "http://localhost:26657/".to_owned(),
    }
}

pub(crate) fn ask_passphrase() -> Result<SecStr> {
    ask("Enter passphrase: ");
    Ok(password().context(ErrorKind::IoError)?.into())
}
