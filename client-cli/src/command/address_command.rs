use std::str::FromStr;

use quest::{ask, success};
use structopt::StructOpt;
use unicase::eq_ascii;

use client_common::{Error, ErrorKind, Result};
use client_core::WalletClient;

use crate::ask_passphrase;

#[derive(Debug)]
pub enum AddressType {
    Transfer,
    Staking,
}

impl FromStr for AddressType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if eq_ascii(s, "transfer") {
            Ok(AddressType::Transfer)
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
    #[structopt(name = "new", about = "New address")]
    New {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
        #[structopt(name = "type", short, long, help = "Type of address to create")]
        address_type: AddressType,
    },
    #[structopt(name = "list", about = "List all addresses for a wallet")]
    List {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
        #[structopt(name = "type", short, long, help = "Type of address to create")]
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
        }
    }

    fn new_address<T: WalletClient>(
        wallet_client: T,
        name: &str,
        address_type: &AddressType,
    ) -> Result<()> {
        let passphrase = ask_passphrase(None)?;

        match address_type {
            AddressType::Staking => {
                let address = wallet_client.new_staking_address(name, &passphrase)?;
                success(&format!("New address: {}", address));
                Ok(())
            }
            AddressType::Transfer => {
                let address = wallet_client.new_transfer_address(name, &passphrase)?;
                success(&format!("New address: {}", address));
                Ok(())
            }
        }
    }

    fn list_addresses<T: WalletClient>(
        wallet_client: T,
        name: &str,
        address_type: &AddressType,
    ) -> Result<()> {
        let passphrase = ask_passphrase(None)?;

        match address_type {
            AddressType::Staking => {
                let addresses = wallet_client.staking_addresses(name, &passphrase)?;

                for address in addresses {
                    ask("Address: ");
                    success(&format!("{}", address));
                }
            }
            AddressType::Transfer => {
                let addresses = wallet_client.transfer_addresses(name, &passphrase)?;

                for address in addresses {
                    ask("Address: ");
                    success(&format!("{}", address));
                }
            }
        }

        Ok(())
    }
}
