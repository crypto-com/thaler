use quest::success;
use structopt::StructOpt;

use client_common::{PublicKey, Result};
use client_core::types::AddressType;
use client_core::WalletClient;

use crate::ask_seckey;

#[derive(Debug, StructOpt)]
pub enum MultiSigCommand {
    #[structopt(
        name = "new-address-public-key",
        about = "Creates a new public key for MultiSig address"
    )]
    NewAddressPublicKey {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
    },

    #[structopt(
        name = "list-address-public-keys",
        about = "List public keys for MultiSig address"
    )]
    ListAddressPublicKeys {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
    },
}

impl MultiSigCommand {
    pub fn execute<T: WalletClient>(&self, wallet_client: T) -> Result<()> {
        match self {
            MultiSigCommand::NewAddressPublicKey { name } => {
                new_address_public_key(wallet_client, name)
            }
            MultiSigCommand::ListAddressPublicKeys { name } => {
                list_address_public_keys(wallet_client, name)
            }
        }
    }
}

fn new_address_public_key<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
    let enckey = ask_seckey(None)?;

    let public_key = wallet_client
        .new_public_key(name, &enckey, Some(AddressType::Transfer))
        .map(|public_key| public_key.to_string())?;

    success(&format!("Public key: {}", public_key));

    Ok(())
}

fn list_address_public_keys<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
    let enckey = ask_seckey(None)?;

    let public_keys: Vec<PublicKey> = wallet_client
        .public_keys(name, &enckey)
        .map(|keys| keys.into_iter().collect())?;

    if public_keys.is_empty() {
        success("No public key found!");
        return Ok(());
    }
    for public_key in public_keys {
        success(&format!("Public key: {}", public_key.to_string()))
    }

    Ok(())
}
