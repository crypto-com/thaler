mod address_command;
mod transaction_command;
mod wallet_command;

use hex::encode;
use prettytable::{cell, format, row, Cell, Row, Table};
use quest::success;
use structopt::StructOpt;

use client_common::balance::BalanceChange;
use client_common::Result;
use client_core::WalletClient;

use self::address_command::AddressCommand;
use self::transaction_command::TransactionCommand;
use self::wallet_command::WalletCommand;

use crate::ask_passphrase;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "client-cli",
    about = "Basic CLI tool for interacting with Crypto.com Chain"
)]
pub enum Command {
    #[structopt(name = "wallet", about = "Wallet operations")]
    Wallet {
        #[structopt(subcommand)]
        wallet_command: WalletCommand,
    },
    #[structopt(name = "address", about = "Address operations")]
    Address {
        #[structopt(subcommand)]
        address_command: AddressCommand,
    },
    #[structopt(name = "balance", about = "Get balance of a wallet")]
    Balance {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
    },
    #[structopt(name = "history", about = "Get transaction history of a wallet")]
    History {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
    },
    #[structopt(name = "transaction", about = "Transaction operations")]
    Transaction {
        #[structopt(subcommand)]
        transaction_command: TransactionCommand,
    },
}

impl Command {
    pub fn execute<T: WalletClient>(&self, wallet_client: T) -> Result<()> {
        match self {
            Command::Wallet { wallet_command } => wallet_command.execute(wallet_client),
            Command::Address { address_command } => address_command.execute(wallet_client),
            Command::Balance { name } => Self::get_balance(wallet_client, name),
            Command::History { name } => Self::get_history(wallet_client, name),
            Command::Transaction {
                transaction_command,
            } => transaction_command.execute(wallet_client),
        }
    }

    fn get_balance<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase()?;
        wallet_client.sync()?;
        let balance = wallet_client.balance(name, &passphrase)?;

        success(&format!("Wallet balance: {}", balance));
        Ok(())
    }

    fn get_history<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase()?;
        wallet_client.sync()?;
        let history = wallet_client.history(name, &passphrase)?;

        if !history.is_empty() {
            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
            table.set_titles(row![
                "Transaction ID",
                "Address",
                "Amount",
                "In/Out",
                "Block Height",
                "Block Time",
            ]);

            for change in history {
                let (amount, in_out, spec) = match change.balance_change {
                    BalanceChange::Incoming(amount) => (amount, "IN", "Fg"),
                    BalanceChange::Outgoing(amount) => (amount, "OUT", "FR"),
                };

                table.add_row(Row::new(vec![
                    Cell::new(&encode(&change.transaction_id)),
                    Cell::from(&change.address),
                    Cell::from(&amount).style_spec("r"),
                    Cell::new(in_out).style_spec(spec),
                    Cell::from(&change.height).style_spec("r"),
                    Cell::from(&change.time),
                ]));
            }

            table.printstd();
        } else {
            success("No history found!")
        }

        Ok(())
    }
}
