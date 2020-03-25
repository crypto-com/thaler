use std::str::FromStr;

use quest::{ask, success, text};
use structopt::StructOpt;
use unicase::eq_ascii;

use client_common::{error::ResultExt, Error, ErrorKind, PublicKey, Result};
use client_core::WalletClient;

use crate::{ask_hardware_kind, ask_seckey};
use client_core::types::WalletKind;

const ADDRESS_TYPE_VARIANTS: [&str; 2] = ["transfer", "staking"];

#[derive(Debug)]
pub enum AddressType {
    Transfer,
    TransferWatch,
    Staking,
}

impl FromStr for AddressType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if eq_ascii(s, "transfer") {
            Ok(AddressType::Transfer)
        } else if eq_ascii(s, "transfer-watch") {
            Ok(AddressType::TransferWatch)
        } else if eq_ascii(s, "staking") {
            Ok(AddressType::Staking)
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Address type can either be `transfer` or `staking`",
            ))
        }
    }
}

#[derive(Debug, StructOpt)]
pub enum AddressCommand {
    #[structopt(name = "new", about = "Creates a new address")]
    New {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
        #[structopt(
            name = "address type",
            short = "t",
            long = "type",
            help = "Type of address to create",
            possible_values = &ADDRESS_TYPE_VARIANTS,
            case_insensitive = true
        )]
        address_type: AddressType,
    },
    #[structopt(name = "list", about = "List all addresses for a wallet")]
    List {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
        #[structopt(
            name = "address type",
            short = "t",
            long = "type",
            help = "Type of address to create",
            possible_values = &ADDRESS_TYPE_VARIANTS,
            case_insensitive = true
        )]
        address_type: AddressType,
    },
    #[structopt(name = "list-pub-key", about = "Shows the public keys of a wallet")]
    ListPubKey {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
        #[structopt(
            name = "address type",
            short = "t",
            long = "type",
            help = "Type of public keys to show",
            possible_values = &ADDRESS_TYPE_VARIANTS,
            case_insensitive = true
        )]
        address_type: AddressType,
    },
}

impl AddressCommand {
    pub fn execute<T: WalletClient>(&self, wallet_client: T) -> Result<()> {
        match self {
            AddressCommand::New { name, address_type } => {
                Self::new_address(wallet_client, name, address_type)
            }
            AddressCommand::List { name, address_type } => {
                Self::list_addresses(wallet_client, name, address_type)
            }
            AddressCommand::ListPubKey { name, address_type } => {
                Self::list_pubkeys(wallet_client, name, address_type)
            }
        }
    }

    fn new_address<T: WalletClient>(
        mut wallet_client: T,
        name: &str,
        address_type: &AddressType,
    ) -> Result<()> {
        let enckey = ask_seckey(None)?;
        let wallet_kind = wallet_client.get_wallet_kind(name, &enckey)?;
        if wallet_kind == WalletKind::HW {
            let hw_kind = ask_hardware_kind(None)?;
            wallet_client.update_hw_service(hw_kind);
        }
        match address_type {
            AddressType::Staking => {
                let address = wallet_client.new_staking_address(name, &enckey)?;
                success(&format!("New address: {}", address));
                Ok(())
            }
            AddressType::Transfer => {
                let address = wallet_client.new_transfer_address(name, &enckey)?;
                success(&format!("New address: {}", address));
                Ok(())
            }
            AddressType::TransferWatch => {
                let enckey = ask_seckey(None)?;
                let public_key = ask_public_key(None)?;
                let address =
                    wallet_client.new_watch_staking_address(name, &enckey, &public_key)?;
                success(&format!("New watch transfer address: {}", address));
                Ok(())
            }
        }
    }

    fn list_addresses<T: WalletClient>(
        wallet_client: T,
        name: &str,
        address_type: &AddressType,
    ) -> Result<()> {
        let enckey = ask_seckey(None)?;

        match address_type {
            AddressType::Staking => {
                let addresses = wallet_client.staking_addresses(name, &enckey)?;

                if !addresses.is_empty() {
                    for address in addresses {
                        ask("Address: ");
                        success(&format!("{}", address));
                    }
                } else {
                    success("No addresses found!")
                }
            }
            AddressType::Transfer | AddressType::TransferWatch => {
                let addresses = wallet_client.transfer_addresses(name, &enckey)?;

                if !addresses.is_empty() {
                    for address in addresses {
                        ask("Address: ");
                        success(&format!("{}", address));
                    }
                } else {
                    success("No addresses found!")
                }
            }
        }

        Ok(())
    }

    fn list_pubkeys<T: WalletClient>(
        wallet_client: T,
        name: &str,
        address_type: &AddressType,
    ) -> Result<()> {
        let enckey = ask_seckey(None)?;

        let pub_keys = match address_type {
            AddressType::Staking => wallet_client.staking_keys(name, &enckey)?,
            AddressType::Transfer | AddressType::TransferWatch => {
                wallet_client.public_keys(name, &enckey)?
            }
        };
        for pubkey in pub_keys.iter() {
            println!("{}", pubkey);
        }

        Ok(())
    }
}

fn ask_public_key(message: Option<&str>) -> Result<PublicKey> {
    ask(message.unwrap_or("Enter public key: "));
    let pubkey_str = text().chain(|| (ErrorKind::InvalidInput, "Invalid input"))?;
    let pubkey_str = pubkey_str.trim();
    let pubkey = PublicKey::from_str(pubkey_str)
        .chain(|| (ErrorKind::InvalidInput, "Invalid public key"))?;
    Ok(pubkey)
}
