mod address_command;
mod transaction_command;
mod wallet_command;

use std::sync::mpsc::channel;
use std::thread;

use chrono::{DateTime, Local, NaiveDateTime, Utc};
use hex::encode;
use pbr::ProgressBar;
use prettytable::{cell, format, row, Cell, Row, Table};
use quest::success;
use structopt::StructOpt;

use self::address_command::AddressCommand;
use self::transaction_command::TransactionCommand;
use self::wallet_command::WalletCommand;
use chain_core::init::coin::Coin;
use chain_core::state::account::StakedStateAddress;
use client_common::storage::SledStorage;
use client_common::tendermint::{Client, WebsocketRpcClient};
use client_common::{Result, Storage};
use client_core::cipher::MockAbciTransactionObfuscation;
use client_core::handler::{DefaultBlockHandler, DefaultTransactionHandler};
use client_core::signer::DefaultSigner;
use client_core::synchronizer::{ManualSynchronizer, ProgressReport};
use client_core::transaction_builder::DefaultTransactionBuilder;
use client_core::types::BalanceChange;
use client_core::wallet::{DefaultWalletClient, WalletClient};
use client_core::BlockHandler;
use client_network::network_ops::{DefaultNetworkOpsClient, NetworkOpsClient};

use crate::{ask_passphrase, storage_path, tendermint_url};

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
    #[structopt(name = "view-key", about = "Shows the view key of a wallet")]
    ViewKey {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
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
    #[structopt(name = "state", about = "Get staked state of an address")]
    StakedState {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
        #[structopt(name = "address", short, long, help = "Staking address")]
        address: StakedStateAddress,
    },
    #[structopt(name = "sync", about = "Synchronize client with Crypto.com Chain")]
    Sync {
        #[structopt(name = "name", short, long, help = "Name of wallet")]
        name: String,
        #[structopt(
            name = "batch-size",
            short,
            long,
            help = "Number of requests per batch in RPC calls to tendermint"
        )]
        batch_size: Option<usize>,
        #[structopt(
            name = "force",
            short,
            long,
            help = "Force synchronization from genesis"
        )]
        force: bool,
    },
}

impl Command {
    pub fn execute(&self) -> Result<()> {
        match self {
            Command::Wallet { wallet_command } => {
                let storage = SledStorage::new(storage_path())?;
                let wallet_client = DefaultWalletClient::new_read_only(storage);
                wallet_command.execute(wallet_client)
            }
            Command::Address { address_command } => {
                let storage = SledStorage::new(storage_path())?;
                let wallet_client = DefaultWalletClient::new_read_only(storage);
                address_command.execute(wallet_client)
            }
            Command::ViewKey { name } => {
                let storage = SledStorage::new(storage_path())?;
                let wallet_client = DefaultWalletClient::new_read_only(storage);

                Self::get_view_key(wallet_client, name)
            }
            Command::Balance { name } => {
                let storage = SledStorage::new(storage_path())?;
                let wallet_client = DefaultWalletClient::new_read_only(storage);
                Self::get_balance(wallet_client, name)
            }
            Command::History { name } => {
                let storage = SledStorage::new(storage_path())?;
                let wallet_client = DefaultWalletClient::new_read_only(storage);
                Self::get_history(wallet_client, name)
            }
            Command::Transaction {
                transaction_command,
            } => {
                let storage = SledStorage::new(storage_path())?;
                let tendermint_client = WebsocketRpcClient::new(&tendermint_url())?;
                let signer = DefaultSigner::new(storage.clone());
                let fee_algorithm = tendermint_client.genesis()?.fee_policy();
                let transaction_obfuscation =
                    MockAbciTransactionObfuscation::new(tendermint_client.clone());
                let transaction_builder = DefaultTransactionBuilder::new(
                    signer.clone(),
                    fee_algorithm,
                    transaction_obfuscation.clone(),
                );

                let wallet_client = DefaultWalletClient::new(
                    storage,
                    tendermint_client.clone(),
                    transaction_builder,
                );
                let network_ops_client = DefaultNetworkOpsClient::new(
                    wallet_client,
                    signer,
                    tendermint_client,
                    fee_algorithm,
                    transaction_obfuscation,
                );
                transaction_command.execute(network_ops_client.get_wallet(), &network_ops_client)
            }
            Command::StakedState { name, address } => {
                let storage = SledStorage::new(storage_path())?;
                let tendermint_client = WebsocketRpcClient::new(&tendermint_url())?;
                let signer = DefaultSigner::new(storage.clone());
                let fee_algorithm = tendermint_client.genesis()?.fee_policy();
                let transaction_obfuscation =
                    MockAbciTransactionObfuscation::new(tendermint_client.clone());
                let transaction_builder = DefaultTransactionBuilder::new(
                    signer.clone(),
                    fee_algorithm,
                    transaction_obfuscation.clone(),
                );
                let wallet_client = DefaultWalletClient::new(
                    storage,
                    tendermint_client.clone(),
                    transaction_builder,
                );

                let network_ops_client = DefaultNetworkOpsClient::new(
                    wallet_client,
                    signer,
                    tendermint_client,
                    fee_algorithm,
                    transaction_obfuscation,
                );
                Self::get_staked_stake(&network_ops_client, name, address)
            }
            Command::Sync {
                name,
                batch_size,
                force,
            } => {
                let storage = SledStorage::new(storage_path())?;
                let tendermint_client = WebsocketRpcClient::new(&tendermint_url())?;

                let transaction_handler = DefaultTransactionHandler::new(storage.clone());
                let transaction_obfuscation =
                    MockAbciTransactionObfuscation::new(tendermint_client.clone());
                let block_handler = DefaultBlockHandler::new(
                    transaction_obfuscation,
                    transaction_handler,
                    storage.clone(),
                );

                let synchronizer =
                    ManualSynchronizer::new(storage, tendermint_client, block_handler);

                Self::resync(synchronizer, name, *batch_size, *force)
            }
        }
    }

    fn get_staked_stake<N: NetworkOpsClient>(
        network_ops_client: &N,
        name: &str,
        address: &StakedStateAddress,
    ) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        let staked_state = network_ops_client.get_staked_state(name, &passphrase, address)?;

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_LINESEP);

        table.set_titles(row!["Nonce", format!("{}", staked_state.nonce)]);
        table.add_row(Row::new(vec![
            Cell::from(&"Bonded".to_string()),
            Cell::from(&format!("{}", staked_state.bonded)),
        ]));
        table.add_row(Row::new(vec![
            Cell::from(&"Unbonded".to_string()),
            Cell::from(&format!("{}", staked_state.unbonded)),
        ]));
        table.add_row(Row::new(vec![
            Cell::from(&"Unbonded From".to_string()),
            Cell::from(&format!(
                "{}",
                <DateTime<Local>>::from(DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp(staked_state.unbonded_from, 0),
                    Utc
                ))
            )),
        ]));

        table.printstd();

        Ok(())
    }

    fn get_view_key<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        let view_key = wallet_client.view_key(name, &passphrase)?;

        success(&format!("View Key: {}", view_key));
        Ok(())
    }

    fn get_balance<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        let balance = wallet_client.balance(name, &passphrase)?;

        success(&format!("Wallet balance: {}", balance));
        Ok(())
    }

    fn get_history<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let passphrase = ask_passphrase(None)?;
        let history = wallet_client.history(name, &passphrase)?;

        if !history.is_empty() {
            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
            table.set_titles(row![
                "Transaction ID",
                "In/Out",
                "Amount",
                "Fee",
                "Block Height",
                "Block Time",
            ]);

            for change in history {
                let (amount, fee, in_out, spec) = match change.balance_change {
                    BalanceChange::Incoming { value } => (value, None, "IN", "Fg"),
                    BalanceChange::Outgoing { value, fee } => (value, Some(fee), "OUT", "FR"),
                    BalanceChange::NoChange => (Coin::zero(), None, "NO CHANGE", "FB"),
                };

                table.add_row(Row::new(vec![
                    Cell::new(&encode(&change.transaction_id)),
                    Cell::new(in_out).style_spec(spec),
                    Cell::from(&amount).style_spec("r"),
                    Cell::new(
                        &fee.as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "-".to_owned()),
                    )
                    .style_spec("r"),
                    Cell::from(&change.block_height).style_spec("r"),
                    Cell::from(&change.block_time),
                ]));
            }

            table.printstd();
        } else {
            success("No history found!")
        }

        Ok(())
    }

    fn resync<S: Storage, C: Client, H: BlockHandler>(
        synchronizer: ManualSynchronizer<S, C, H>,
        name: &str,
        batch_size: Option<usize>,
        force: bool,
    ) -> Result<()> {
        let passphrase = ask_passphrase(None)?;

        let (sender, receiver) = channel();

        let handle = thread::spawn(move || {
            let mut init_block_height = 0;
            let mut final_block_height = 0;
            let mut progress_bar = None;

            for progress_report in receiver.iter() {
                match progress_report {
                    ProgressReport::Init {
                        start_block_height,
                        finish_block_height,
                    } => {
                        init_block_height = start_block_height;
                        final_block_height = finish_block_height;
                        progress_bar =
                            Some(ProgressBar::new(finish_block_height - start_block_height));

                        let pb = progress_bar.as_mut().unwrap();
                        pb.message("Synchronizing: ");
                    }
                    ProgressReport::Update {
                        current_block_height,
                    } => {
                        if let Some(ref mut pb) = progress_bar {
                            if current_block_height == final_block_height {
                                pb.finish_println("Synchronization complete!");
                            } else {
                                pb.set(current_block_height - init_block_height);
                            }
                        }
                    }
                }
            }
        });

        if force {
            synchronizer.sync_all(name, &passphrase, batch_size, Some(sender))?;
        } else {
            synchronizer.sync(name, &passphrase, batch_size, Some(sender))?;
        }

        let _ = handle.join();

        Ok(())
    }
}
