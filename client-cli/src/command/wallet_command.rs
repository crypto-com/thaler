use quest::{ask, error, success, text};
use secstr::SecUtf8;
use structopt::StructOpt;

use client_common::{Error, ErrorKind, PrivateKey, Result, ResultExt};
use client_core::types::WalletKind;
use client_core::{Mnemonic, WalletClient};

use crate::{ask_passphrase, ask_seckey};
use client_core::service::WalletInfo;
use client_core::wallet::WalletRequest;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

const WALLET_KIND_VARIANTS: [&str; 3] = ["basic", "hd", "hw"];

#[derive(Debug, StructOpt)]
pub enum WalletCommand {
    #[structopt(name = "new", about = "New wallet")]
    New {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
        #[structopt(
            name = "wallet type",
            short = "t",
            long = "type",
            help = "Type of wallet to create",
            possible_values = &WALLET_KIND_VARIANTS,
            case_insensitive = true
        )]
        wallet_type: WalletKind,
        #[structopt(
            name = "wallet mnemonic count",
            short = "m",
            long = "mnemonics_word_count",
            default_value = "24",
            help = "Number of words in mnemonics"
        )]
        mnemonics_word_count: u32,
    },
    #[structopt(name = "export", about = "Backup wallet to a file")]
    Export {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet (comma separated if many) "
        )]
        name: Option<String>,
        #[structopt(
            name = "from_file",
            short = "f",
            long = "from_file",
            parse(from_os_str),
            help = r#"json file contains a list of {"name": wallet_name, "auth_token": auth_token}"#
        )]
        from_file: Option<PathBuf>,
        #[structopt(
            name = "to_file",
            short = "t",
            long = "to_file",
            parse(from_os_str),
            help = "file to dump the wallet information"
        )]
        to_file: Option<PathBuf>,
    },
    #[structopt(name = "import", about = "Import a wallet from a file")]
    Import {
        #[structopt(
            name = "file",
            short = "f",
            long = "file",
            parse(from_os_str),
            help = "file stored the wallet info"
        )]
        file: PathBuf,
    },
    #[structopt(name = "list", about = "List all wallets")]
    List,
    #[structopt(name = "restore", about = "Restore HD Wallet")]
    Restore {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
    },
    #[structopt(name = "restore-basic", about = "Restore watch-only Wallet")]
    RestoreBasic {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
    },
    #[structopt(name = "auth-token", about = "Get authentication token")]
    AuthToken {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
    },
    #[structopt(name = "delete", about = "Delete wallet")]
    Delete {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
    },
}

impl WalletCommand {
    pub fn execute<T: WalletClient>(&self, wallet_client: T) -> Result<()> {
        match self {
            WalletCommand::New {
                name,
                wallet_type,
                mnemonics_word_count,
            } => Self::new_wallet(wallet_client, name, *wallet_type, *mnemonics_word_count),
            WalletCommand::List => Self::list_wallets(wallet_client),
            WalletCommand::Restore { name } => Self::restore_wallet(wallet_client, name),
            WalletCommand::RestoreBasic { name } => Self::restore_basic_wallet(wallet_client, name),
            WalletCommand::AuthToken { name } => Self::auth_token(wallet_client, name),
            WalletCommand::Delete { name } => Self::delete(wallet_client, name),
            WalletCommand::Export {
                name,
                from_file,
                to_file,
            } => Self::export(wallet_client, name, from_file, to_file),
            WalletCommand::Import { file } => Self::import(wallet_client, file),
        }
    }

    fn new_wallet<T: WalletClient>(
        wallet_client: T,
        name: &str,
        wallet_kind: WalletKind,
        mnemonics_word_count: u32,
    ) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        let confirmed_passphrase = ask_passphrase(Some("Confirm passphrase: "))?;

        if passphrase != confirmed_passphrase {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Passphrases do not match",
            ));
        }
        let (enckey, mnemonic) =
            wallet_client.new_wallet(name, &passphrase, wallet_kind, Some(mnemonics_word_count))?;

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

    fn export<T: WalletClient>(
        wallet_client: T,
        name: &Option<String>,
        from_file: &Option<PathBuf>,
        to_file: &Option<PathBuf>,
    ) -> Result<()> {
        let mut wallet_info_list = vec![];
        let mut error_wallets = vec![];
        match (name, from_file) {
            (Some(_name), Some(_from_file)) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "only need name or from_file",
                ))
            }
            (None, None) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "need name or from_file",
                ))
            }
            (Some(names), None) => {
                for name in names.split(',') {
                    let enckey =
                        ask_seckey(Some(&format!("Enter authentication token for {}: ", name)))?;
                    let wallet_info = wallet_client.export_wallet(name, &enckey)?;
                    wallet_info_list.push(wallet_info);
                }
            }
            (None, Some(from_file)) => {
                let settings = std::fs::read_to_string(from_file)
                    .chain(|| (ErrorKind::IoError, "Unable to read from file"))?;
                let wallet_requests: Vec<WalletRequest> = serde_json::from_str(&settings)
                    .chain(|| (ErrorKind::InvalidInput, "Invalid wallet info"))?;
                for request in wallet_requests {
                    match wallet_client.export_wallet(&request.name, &request.enckey) {
                        Ok(wallet_info) => {
                            wallet_info_list.push(wallet_info);
                        }
                        Err(e) => {
                            error(&format!("error to get wallet info: {:?}", e));
                            error_wallets.push(request.name.clone());
                        }
                    }
                }
            }
        }
        if error_wallets.is_empty() {
            success(&format!("Get all {} wallets info.", wallet_info_list.len()));
        } else {
            error(&format!(
                "Get {} wallets info, failed wallet(s): {}, please fix and retry!",
                wallet_info_list.len(),
                error_wallets.join(",")
            ));
            return Ok(());
        }
        let wallet_info_str = serde_json::to_string_pretty(&wallet_info_list).chain(|| {
            (
                ErrorKind::SerializationError,
                "Inner serialize wallet info error",
            )
        })?;
        match to_file {
            Some(to_file) => {
                let mut file = File::create(to_file)
                    .chain(|| (ErrorKind::IoError, "Unable to create file"))?;
                file.write_all(wallet_info_str.as_bytes())
                    .chain(|| (ErrorKind::IoError, "Unable to write to file"))?;
                let msg = format!(
                    "Export {} wallet to file {:?} success",
                    wallet_info_list.len(),
                    to_file
                );
                success(&msg);
            }
            None => {
                success(&wallet_info_str);
            }
        }
        Ok(())
    }

    fn import<T: WalletClient>(wallet_client: T, file: &PathBuf) -> Result<()> {
        let wallet_info_str = std::fs::read_to_string(file)
            .chain(|| (ErrorKind::IoError, "Unable to read from file"))?;

        let wallet_info_list: Vec<WalletInfo> = serde_json::from_str(&wallet_info_str)
            .chain(|| (ErrorKind::InvalidInput, "Invalid wallet info list"))?;
        for mut wallet_info in wallet_info_list {
            let name = wallet_info.name.clone();
            let passphrase = match &wallet_info.passphrase {
                Some(p) => p.clone(),
                None => ask_passphrase(Some(&format!("Input passphrase for wallet {}:", name)))?,
            };
            let enckey = wallet_client.import_wallet(&name, &passphrase, &mut wallet_info);
            match enckey {
                Ok(enckey) => success(&format!(
                    "Authentication token of wallet {}: {}",
                    name,
                    &hex::encode(enckey.unsecure())
                )),
                Err(e) => error(&format!("Import wallet {} failed: {:?}", name, e)),
            }
        }
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

    fn restore_basic_wallet<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        let confirmed_passphrase = ask_passphrase(Some("Confirm passphrase: "))?;

        if passphrase != confirmed_passphrase {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Passphrases do not match",
            ));
        }

        let private_view_key = ask_private_view_key()?;

        let enckey = wallet_client.restore_basic_wallet(name, &passphrase, &private_view_key)?;

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

    fn delete<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        wallet_client.delete_wallet(name, &passphrase)?;
        Ok(())
    }
}

fn ask_mnemonic(message: Option<&str>) -> Result<Mnemonic> {
    ask(message.unwrap_or("Enter mnemonic: "));
    let mnemonic = SecUtf8::from(text().chain(|| (ErrorKind::IoError, "Unable to read mnemonic"))?);

    Mnemonic::from_secstr(&mnemonic)
}

fn ask_private_view_key() -> Result<PrivateKey> {
    ask("Enter private view key: ");

    let view_key_str = text().chain(|| (ErrorKind::IoError, "Unable to read view keys"))?;

    if view_key_str.is_empty() {
        Err(Error::new(ErrorKind::InvalidInput, "need private view key"))
    } else {
        let view_key = &hex::decode(view_key_str.trim())
            .chain(|| (ErrorKind::InvalidInput, "invalid view_key"))?;
        let view_key = PrivateKey::deserialize_from(view_key)
            .chain(|| (ErrorKind::InvalidInput, "invalid private view key"))?;
        Ok(view_key)
    }
}
