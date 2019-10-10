use client_common::{Error, ErrorKind, Result};
use client_core::WalletClient;
use quest::{ask, success};
use structopt::StructOpt;

use crate::ask_passphrase;
use client_core::types::WalletKind;
use secstr::*;
#[derive(Debug, StructOpt)]
pub enum WalletCommand {
    #[structopt(name = "new", about = "New wallet")]
    New {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
        #[structopt(
            name = "type",
            short,
            long,
            help = "Type of wallet to create (hd, basic)"
        )]
        wallet_type: WalletKind,
    },
    #[structopt(name = "list", about = "List all wallets")]
    List,
    #[structopt(name = "restore", about = "Restore HD Wallet")]
    Restore {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
    },
}

impl WalletCommand {
    pub fn execute<T: WalletClient>(&self, wallet_client: T) -> Result<()> {
        match self {
            WalletCommand::New { name, wallet_type } => {
                Self::new_wallet(wallet_client, name, *wallet_type)
            }
            WalletCommand::List => Self::list_wallets(wallet_client),
            WalletCommand::Restore { name } => Self::restore_wallet(wallet_client, name),
        }
    }

    fn get_mnemonics() -> Result<SecUtf8> {
        let mut mnemonics: String;
        loop {
            println!("enter mnemonics=");
            mnemonics = quest::text()
                .map_err(|_e| Error::new(ErrorKind::InvalidInput, "get_mnemonics quest text"))?
                .to_string();
            println!("mnemonics={}", mnemonics);
            println!("enter y to conitnue");
            let r = quest::yesno(false)
                .map_err(|_e| Error::new(ErrorKind::InvalidInput, "get_mnemonics quest yesno"))?;
            if r.is_some() && *r.as_ref().unwrap() {
                break;
            }
        }
        Ok(SecUtf8::from(mnemonics))
    }
    fn new_wallet<T: WalletClient>(
        wallet_client: T,
        name: &str,
        walletkind: WalletKind,
    ) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        let confirmed_passphrase = ask_passphrase(Some("Confirm passphrase: "))?;

        if passphrase != confirmed_passphrase {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Passphrases do not match",
            ));
        }

        if WalletKind::HD == walletkind {
            let mnemonics = wallet_client.new_mnemonics()?;
            let mnemonics_phrase = SecUtf8::from(mnemonics.to_string());
            println!("ok keep mnemonics safely = {}", mnemonics_phrase.unsecure());
            wallet_client.new_hdwallet(name, &passphrase, &mnemonics_phrase)?;
        }
        println!("--------------------------------------------");
        wallet_client.new_wallet(name, &passphrase)?;
        success(&format!("Wallet created with name: {}", name));
        Ok(())
    }

    fn restore_wallet<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        let confirmed_passphrase = ask_passphrase(Some("Confirm passphrase: "))?;

        if passphrase != confirmed_passphrase {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Passphrases do not match",
            ));
        }

        let mnemonic_phrase = WalletCommand::get_mnemonics()?;
        wallet_client.new_hdwallet(name, &passphrase, &mnemonic_phrase)?;
        println!("--------------------------------------------");
        wallet_client.new_wallet(name, &passphrase)?;
        success(&format!("Wallet restore with name: {}", name));
        Ok(())
    }
    fn list_wallets<T: WalletClient>(wallet_client: T) -> Result<()> {
        let wallets = wallet_client.wallets()?;

        if !wallets.is_empty() {
            for wallet in wallets {
                ask("Wallet name: ");
                success(&wallet);
            }
        } else {
            success("No wallets found!")
        }

        Ok(())
    }
}
