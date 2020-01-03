use quest::{ask, success, text};
use secstr::SecUtf8;
use structopt::StructOpt;

use client_common::{Error, ErrorKind, Result, ResultExt};
use client_core::types::WalletKind;
use client_core::{Mnemonic, WalletClient};

use crate::ask_passphrase;

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
    #[structopt(name = "auth-token", about = "Get authentication token")]
    AuthToken {
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
            WalletCommand::AuthToken { name } => Self::auth_token(wallet_client, name),
        }
    }

    fn new_wallet<T: WalletClient>(
        wallet_client: T,
        name: &str,
        wallet_kind: WalletKind,
    ) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        let confirmed_passphrase = ask_passphrase(Some("Confirm passphrase: "))?;

        if passphrase != confirmed_passphrase {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Passphrases do not match",
            ));
        }

        let (enckey, mnemonic) = wallet_client.new_wallet(name, &passphrase, wallet_kind)?;

        if let WalletKind::HD = wallet_kind {
            ask("Please store following mnemonic safely to restore your wallet later: ");
            println!();
            success(&format!(
                "Mnemonic: {}",
                &mnemonic.unwrap().unsecure_phrase()
            ));
        }

        success(&format!(
            "Authentication token: {}",
            &hex::encode(enckey.unsecure())
        ));
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

        let mnemonic = ask_mnemonic(None)?;
        let confirmed_mnemonic = ask_mnemonic(Some("Confirm mnemonic: "))?;

        if mnemonic.as_ref() != confirmed_mnemonic.as_ref() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Mnemonics do not match",
            ));
        }

        let enckey = wallet_client.restore_wallet(name, &passphrase, &mnemonic)?;

        mnemonic.zeroize();

        success(&format!(
            "Authentication token: {}",
            &hex::encode(enckey.unsecure())
        ));
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

    fn auth_token<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        let enckey = wallet_client.auth_token(name, &passphrase)?;
        success(&format!(
            "Authentication token: {}",
            &hex::encode(enckey.unsecure())
        ));
        Ok(())
    }
}

fn ask_mnemonic(message: Option<&str>) -> Result<Mnemonic> {
    ask(message.unwrap_or("Enter mnemonic: "));
    let mnemonic = SecUtf8::from(text().chain(|| (ErrorKind::IoError, "Unable to read mnemonic"))?);

    Mnemonic::from_secstr(&mnemonic)
}
