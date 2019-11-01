mod address_command;
mod transaction_command;
mod wallet_command;

use std::sync::mpsc::channel;
use std::thread;

use chrono::{DateTime, Local, NaiveDateTime, Utc};
use cli_table::format::{CellFormat, Color, Justify};
use cli_table::{Cell, Row, Table};
use hex::encode;
use pbr::ProgressBar;
use quest::success;
use structopt::StructOpt;

use chain_core::init::coin::Coin;
use chain_core::state::account::StakedStateAddress;
use client_common::storage::SledStorage;
use client_common::tendermint::{Client, WebsocketRpcClient};
use client_common::{ErrorKind, Result, ResultExt, Storage};
use client_core::cipher::MockAbciTransactionObfuscation;
use client_core::handler::{DefaultBlockHandler, DefaultTransactionHandler};
use client_core::signer::DefaultSigner;
use client_core::synchronizer::{ManualSynchronizer, ProgressReport};
use client_core::transaction_builder::DefaultTransactionBuilder;
use client_core::types::BalanceChange;
use client_core::wallet::{DefaultWalletClient, WalletClient};
use client_core::BlockHandler;
use client_network::network_ops::{DefaultNetworkOpsClient, NetworkOpsClient};

use self::address_command::AddressCommand;
use self::transaction_command::TransactionCommand;
use self::wallet_command::WalletCommand;
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
                transaction_command
                    .execute(network_ops_client.get_wallet_client(), &network_ops_client)
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

        let bold = CellFormat::builder().bold(true).build();
        let justify_right = CellFormat::builder().justify(Justify::Right).build();

        let table = Table::new(
            vec![
                Row::new(vec![
                    Cell::new("Nonce", bold),
                    Cell::new(&staked_state.nonce, justify_right),
                ]),
                Row::new(vec![
                    Cell::new("Bonded", bold),
                    Cell::new(&staked_state.bonded, justify_right),
                ]),
                Row::new(vec![
                    Cell::new("Unbonded", bold),
                    Cell::new(&staked_state.unbonded, justify_right),
                ]),
                Row::new(vec![
                    Cell::new("Unbonded From", bold),
                    Cell::new(
                        &<DateTime<Local>>::from(DateTime::<Utc>::from_utc(
                            NaiveDateTime::from_timestamp(staked_state.unbonded_from, 0),
                            Utc,
                        )),
                        justify_right,
                    ),
                ]),
                Row::new(vec![
                    Cell::new("Jailed Until", bold),
                    staked_state.jailed_until.map_or_else(
                        || Cell::new("Not jailed", justify_right),
                        |jailed_until| {
                            Cell::new(
                                &<DateTime<Local>>::from(DateTime::<Utc>::from_utc(
                                    NaiveDateTime::from_timestamp(jailed_until, 0),
                                    Utc,
                                )),
                                justify_right,
                            )
                        },
                    ),
                ]),
            ],
            Default::default(),
        );

        table
            .print_stdout()
            .chain(|| (ErrorKind::IoError, "Unable to print table"))?;

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
            let bold = CellFormat::builder().bold(true).build();

            let mut rows = Vec::new();

            rows.push(Row::new(vec![
                Cell::new("Transaction ID", bold),
                Cell::new("In/Out", bold),
                Cell::new("Amount", bold),
                Cell::new("Fee", bold),
                Cell::new("Block Height", bold),
                Cell::new("Block Time", bold),
            ]));

            for change in history {
                let green = CellFormat::builder()
                    .foreground_color(Some(Color::Green))
                    .build();
                let red = CellFormat::builder()
                    .foreground_color(Some(Color::Red))
                    .build();
                let blue = CellFormat::builder()
                    .foreground_color(Some(Color::Blue))
                    .build();

                let right_justify = CellFormat::builder().justify(Justify::Right).build();

                let (amount, fee, in_out, format) = match change.balance_change {
                    BalanceChange::Incoming { value } => (value, None, "IN", green),
                    BalanceChange::Outgoing { value, fee } => (value, Some(fee), "OUT", red),
                    BalanceChange::NoChange => (Coin::zero(), None, "NO CHANGE", blue),
                };

                rows.push(Row::new(vec![
                    Cell::new(&encode(&change.transaction_id), Default::default()),
                    Cell::new(in_out, format),
                    Cell::new(&amount, right_justify),
                    Cell::new(
                        &fee.as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "-".to_owned()),
                        right_justify,
                    ),
                    Cell::new(&change.block_height, right_justify),
                    Cell::new(&change.block_time, Default::default()),
                ]));
            }

            let table = Table::new(rows, Default::default());

            table
                .print_stdout()
                .chain(|| (ErrorKind::IoError, "Unable to print table"))?;
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
