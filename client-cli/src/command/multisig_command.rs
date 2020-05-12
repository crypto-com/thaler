use quest::{ask, success, text};
use std::str::FromStr;
use structopt::StructOpt;

use super::address_command::ask_public_key;
use client_common::{ErrorKind, PublicKey, Result, ResultExt};
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

    #[structopt(name = "new-address", about = "Create a new MultiSig address")]
    CreateMultiSigAddress {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
        #[structopt(
            name = "public keys",
            short = "p",
            long = "public_keys",
            help = "public keys, included self public key, separated by commas"
        )]
        public_keys: Option<String>,
        #[structopt(
            name = "self public key",
            short = "s",
            long = "self_public_key",
            help = "self public key"
        )]
        self_public_key: Option<String>,
        #[structopt(
            name = "number of required signature",
            short = "r",
            long = "required_signature",
            help = "the number of required signature"
        )]
        required_signatures: Option<usize>,
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
            MultiSigCommand::CreateMultiSigAddress {
                name,
                public_keys,
                self_public_key,
                required_signatures,
            } => new_multisign_address(
                wallet_client,
                name,
                public_keys,
                self_public_key,
                required_signatures,
            ),
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

fn new_multisign_address<T: WalletClient>(
    wallet_client: T,
    name: &str,
    public_keys: &Option<String>,
    self_public_key: &Option<String>,
    required_pubkey: &Option<usize>,
) -> Result<()> {
    let enckey = ask_seckey(None)?;
    let public_keys_str = match public_keys {
        None => ask_public_keys(None)?,
        Some(s) => s.clone(),
    };
    let pubkeys = public_keys_str
        .split(',')
        .map(|s| PublicKey::from_str(s.trim()))
        .collect::<Result<Vec<_>>>()
        .chain(|| (ErrorKind::InvalidInput, "Invalid public key"))?;

    let self_public_key = match self_public_key {
        None => ask_public_key(Some("input self pulblic key: "))?,
        Some(p) => PublicKey::from_str(p)?,
    };
    wallet_client
        .private_key(name, &enckey, &self_public_key)
        .chain(|| {
            (
                ErrorKind::InvalidInput,
                "Self public key does not belong to current wallet",
            )
        })?;
    let n = match required_pubkey {
        None => ask_required_signature()?,
        Some(n) => *n,
    };
    let extended_address =
        wallet_client.new_multisig_transfer_address(&name, &enckey, pubkeys, self_public_key, n)?;

    let msg = format!("MultiSign address: {}", extended_address.to_string());
    success(&msg);
    Ok(())
}

fn ask_required_signature() -> Result<usize> {
    ask("how many signatures required: ");
    let n = text().err_kind(ErrorKind::InvalidInput, || {
        "Unable to read required signatures number"
    })?;
    let n = n
        .parse::<usize>()
        .chain(|| (ErrorKind::InvalidInput, "Invalid number"))?;
    Ok(n)
}

pub fn ask_public_keys(message: Option<&str>) -> Result<String> {
    ask(message.unwrap_or("Enter public keys(include self public key, separated by commas): "));
    let pubkeys_str = text().chain(|| (ErrorKind::InvalidInput, "Invalid input"))?;
    Ok(pubkeys_str)
    //    Ok(pubkeys)
}
