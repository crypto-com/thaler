use quest::{ask, success};
use structopt::StructOpt;

use client_common::Result;
use client_core::WalletClient;

use crate::ask_passphrase;

#[derive(Debug, StructOpt)]
pub enum AddressCommand {
    #[structopt(name = "new", about = "New address")]
    New {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
    },
    #[structopt(name = "list", about = "List all addresses for a wallet")]
    List {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
    },
}

impl AddressCommand {
    pub fn execute<T: WalletClient>(&self, wallet_client: T) -> Result<()> {
        match self {
            AddressCommand::New { name } => Self::new_address(wallet_client, name),
            AddressCommand::List { name } => Self::list_addresses(wallet_client, name),
        }
    }

    fn new_address<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase()?;
        let address = wallet_client.new_redeem_address(name, &passphrase)?;

        success(&format!("New address: {}", address));
        Ok(())
    }

    fn list_addresses<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase()?;
        let addresses = wallet_client.addresses(name, &passphrase)?;

        for address in addresses {
            ask("Address: ");
            success(&format!("{}", address));
        }

        Ok(())
    }
}
