mod address_command;
mod multisig_command;
mod transaction_command;
mod wallet_command;

use std::convert::TryInto;
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
#[cfg(not(feature = "mock-enc-dec"))]
use client_common::tendermint::types::AbciQueryExt;
use client_common::tendermint::types::GenesisExt;
use client_common::tendermint::{Client, WebsocketRpcClient};
use client_common::{ErrorKind, Result, ResultExt, SecKey, Storage};
#[cfg(not(feature = "mock-enc-dec"))]
use client_core::cipher::DefaultTransactionObfuscation;
#[cfg(feature = "mock-enc-dec")]
use client_core::cipher::MockAbciTransactionObfuscation;
use client_core::signer::WalletSignerManager;
use client_core::transaction_builder::DefaultWalletTransactionBuilder;
use client_core::types::BalanceChange;
use client_core::wallet::syncer::{ObfuscationSyncerConfig, ProgressReport, WalletSyncer};
use client_core::wallet::{DefaultWalletClient, WalletClient};
use client_core::TransactionObfuscation;
use client_network::network_ops::{DefaultNetworkOpsClient, NetworkOpsClient};
#[cfg(feature = "mock-enc-dec")]
use log::warn;

use self::address_command::AddressCommand;
use self::multisig_command::MultiSigCommand;
use self::transaction_command::TransactionCommand;
use self::wallet_command::WalletCommand;
use crate::{ask_seckey, storage_path, tendermint_url};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "client-cli",
    about = r#"Basic CLI tool for interacting with Crypto.com Chain

ENVIRONMENT VARIABLES:
    CRYPTO_CLIENT_DEBUG             Set to `true` for detailed error messages (Default: `false`)
    CRYPTO_CHAIN_ID                 Chain ID of Crypto.com Chain
    CRYPTO_CLIENT_STORAGE           Storage directory (Default: `.storage`)
    CRYPTO_CLIENT_TENDERMINT        Websocket endpoint for tendermint (Default: `ws://localhost:26657/websocket`)
"#
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
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
        #[structopt(name = "private", short, long, help = "Show private key instead")]
        private: bool,
    },
    #[structopt(name = "balance", about = "Get balance of a wallet")]
    Balance {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
    },
    #[structopt(name = "history", about = "Get transaction history of a wallet")]
    History {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
        #[structopt(name = "offset", short, long, help = "Offset", default_value = "0")]
        offset: usize,
        #[structopt(name = "limit", short, long, help = "Limit", default_value = "100")]
        limit: usize,
        #[structopt(
            name = "reversed",
            short,
            long,
            help = "Reverse order (default is from old to new)"
        )]
        reversed: bool,
    },
    #[structopt(name = "transaction", about = "Transaction operations")]
    Transaction {
        #[structopt(subcommand)]
        transaction_command: TransactionCommand,
    },
    #[structopt(name = "state", about = "Get staked state of an address")]
    StakedState {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
        #[structopt(
            name = "staking address",
            short = "a",
            long = "address",
            help = "Staking address"
        )]
        address: StakedStateAddress,
    },
    #[structopt(name = "sync", about = "Synchronize client with Crypto.com Chain")]
    Sync {
        #[structopt(
            name = "wallet name",
            short = "n",
            long = "name",
            help = "Name of wallet"
        )]
        name: String,
        #[structopt(
            name = "batch-size",
            short,
            long,
            default_value = "20",
            help = "Number of requests per batch in RPC calls to tendermint"
        )]
        batch_size: usize,
        #[structopt(
            name = "force",
            short,
            long,
            help = "Force synchronization from genesis"
        )]
        force: bool,
        #[structopt(
            name = "disable-fast-forward",
            long,
            help = "Disable fast forward, which is not secure when connecting to outside nodes"
        )]
        disable_fast_forward: bool,
        #[structopt(
            name = "block-height-ensure",
            long,
            default_value = "50",
            help = "Number of block height to rollback the utxos in pending transactions"
        )]
        block_height_ensure: u64,
    },
    #[structopt(name = "multisig", about = "MultiSig operations")]
    MultiSig {
        #[structopt(subcommand)]
        multisig_command: MultiSigCommand,
    },
}

/// normal
#[cfg(not(feature = "mock-enc-dec"))]
fn get_tx_query(tendermint_client: WebsocketRpcClient) -> Result<DefaultTransactionObfuscation> {
    let result = tendermint_client.query("txquery", &[])?.bytes()?;
    let address = std::str::from_utf8(&result).chain(|| {
        (
            ErrorKind::ConnectionError,
            "Unable to decode txquery address",
        )
    })?;
    if let Some(hostname) = address.split(':').next() {
        Ok(DefaultTransactionObfuscation::new(
            address.to_string(),
            hostname.to_string(),
        ))
    } else {
        Err(client_common::Error::new(
            ErrorKind::ConnectionError,
            "Unable to decode txquery address",
        ))
    }
}

/// temporary
#[cfg(feature = "mock-enc-dec")]
fn get_tx_query(
    tendermint_client: WebsocketRpcClient,
) -> Result<MockAbciTransactionObfuscation<WebsocketRpcClient>> {
    warn!("WARNING: Using mock (non-enclave) infrastructure");
    Ok(MockAbciTransactionObfuscation::new(tendermint_client))
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
            Command::ViewKey { name, private } => {
                let storage = SledStorage::new(storage_path())?;
                let wallet_client = DefaultWalletClient::new_read_only(storage);

                Self::get_view_key(wallet_client, name, *private)
            }
            Command::Balance { name } => {
                let storage = SledStorage::new(storage_path())?;
                let wallet_client = DefaultWalletClient::new_read_only(storage);
                Self::get_balance(wallet_client, name)
            }
            Command::History {
                name,
                offset,
                limit,
                reversed,
            } => {
                let storage = SledStorage::new(storage_path())?;
                let wallet_client = DefaultWalletClient::new_read_only(storage);
                Self::get_history(wallet_client, name, *offset, *limit, *reversed)
            }
            Command::Transaction {
                transaction_command,
            } => {
                let storage = SledStorage::new(storage_path())?;
                let tendermint_client = WebsocketRpcClient::new(&tendermint_url())?;
                let signer_manager = WalletSignerManager::new(storage.clone());
                let fee_algorithm = tendermint_client.genesis()?.fee_policy();
                let transaction_obfuscation = get_tx_query(tendermint_client.clone())?;
                let transaction_builder = DefaultWalletTransactionBuilder::new(
                    signer_manager.clone(),
                    fee_algorithm,
                    transaction_obfuscation.clone(),
                );

                let wallet_client = DefaultWalletClient::new(
                    storage,
                    tendermint_client.clone(),
                    transaction_builder,
                    None,
                );
                let network_ops_client = DefaultNetworkOpsClient::new(
                    wallet_client,
                    signer_manager,
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
                let signer_manager = WalletSignerManager::new(storage.clone());
                let fee_algorithm = tendermint_client.genesis()?.fee_policy();
                let transaction_obfuscation = get_tx_query(tendermint_client.clone())?;
                let transaction_builder = DefaultWalletTransactionBuilder::new(
                    signer_manager.clone(),
                    fee_algorithm,
                    transaction_obfuscation.clone(),
                );
                let wallet_client = DefaultWalletClient::new(
                    storage,
                    tendermint_client.clone(),
                    transaction_builder,
                    None,
                );

                let network_ops_client = DefaultNetworkOpsClient::new(
                    wallet_client,
                    signer_manager,
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
                disable_fast_forward,
                block_height_ensure,
            } => {
                let tendermint_client = WebsocketRpcClient::new(&tendermint_url())?;
                let tx_obfuscation = get_tx_query(tendermint_client.clone())?;
                let enckey = ask_seckey(None)?;
                let config = ObfuscationSyncerConfig::new(
                    SledStorage::new(storage_path())?,
                    tendermint_client,
                    tx_obfuscation,
                    !*disable_fast_forward,
                    *batch_size,
                    *block_height_ensure,
                );
                Self::resync(config, name.clone(), enckey, *force)
            }
            Command::MultiSig { multisig_command } => {
                let storage = SledStorage::new(storage_path())?;
                let wallet_client = DefaultWalletClient::new_read_only(storage);
                multisig_command.execute(wallet_client)
            }
        }
    }

    fn get_staked_stake<N: NetworkOpsClient>(
        network_ops_client: &N,
        name: &str,
        address: &StakedStateAddress,
    ) -> Result<()> {
        let enckey = ask_seckey(None)?;
        let staked_state = network_ops_client.get_staked_state(name, &enckey, address)?;

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
                            NaiveDateTime::from_timestamp(
                                staked_state.unbonded_from.try_into().unwrap(),
                                0,
                            ),
                            Utc,
                        )),
                        justify_right,
                    ),
                ]),
                Row::new(vec![
                    Cell::new("Jailed Until", bold),
                    staked_state.punishment.as_ref().map_or_else(
                        || Cell::new("Not jailed", justify_right),
                        |punishment| {
                            Cell::new(
                                &<DateTime<Local>>::from(DateTime::<Utc>::from_utc(
                                    NaiveDateTime::from_timestamp(
                                        punishment.jailed_until.try_into().unwrap(),
                                        0,
                                    ),
                                    Utc,
                                )),
                                justify_right,
                            )
                        },
                    ),
                ]),
                Row::new(vec![
                    Cell::new("Punishment Type", bold),
                    staked_state.punishment.as_ref().map_or_else(
                        || Cell::new("Not punished", justify_right),
                        |punishment| Cell::new(&punishment.kind.to_string(), justify_right),
                    ),
                ]),
                Row::new(vec![
                    Cell::new("Slash Amount", bold),
                    staked_state.punishment.as_ref().map_or_else(
                        || Cell::new("Not punished", justify_right),
                        |punishment| {
                            punishment.slash_amount.map_or_else(
                                || Cell::new("Not slashed", justify_right),
                                |slash_amount| Cell::new(&slash_amount, justify_right),
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

    fn get_view_key<T: WalletClient>(wallet_client: T, name: &str, private: bool) -> Result<()> {
        let enckey = ask_seckey(None)?;
        let view_key = if private {
            encode(&wallet_client.view_key_private(name, &enckey)?.serialize())
        } else {
            wallet_client.view_key(name, &enckey)?.to_string()
        };

        success(&format!("View Key: {}", view_key));
        Ok(())
    }

    fn get_balance<T: WalletClient>(wallet_client: T, name: &str) -> Result<()> {
        let enckey = ask_seckey(None)?;
        let balance = wallet_client.balance(name, &enckey)?;

        let rows = vec![
            Row::new(vec![
                Cell::new("Total", Default::default()),
                Cell::new(format!("{}", balance.total).as_str(), Default::default()),
            ]),
            Row::new(vec![
                Cell::new("Pending", Default::default()),
                Cell::new(format!("{}", balance.pending).as_str(), Default::default()),
            ]),
            Row::new(vec![
                Cell::new("Available", Default::default()),
                Cell::new(
                    format!("{}", balance.available).as_str(),
                    Default::default(),
                ),
            ]),
        ];

        let table = Table::new(rows, Default::default());
        table
            .print_stdout()
            .chain(|| (ErrorKind::IoError, "Unable to print table"))?;

        Ok(())
    }

    fn get_history<T: WalletClient>(
        wallet_client: T,
        name: &str,
        offset: usize,
        limit: usize,
        reversed: bool,
    ) -> Result<()> {
        let enckey = ask_seckey(None)?;
        let history = wallet_client.history(name, &enckey, offset, limit, reversed)?;

        if !history.is_empty() {
            let bold = CellFormat::builder().bold(true).build();

            let mut rows = Vec::new();

            rows.push(Row::new(vec![
                Cell::new("Transaction ID", bold),
                Cell::new("In/Out", bold),
                Cell::new("Amount", bold),
                Cell::new("Fee", bold),
                Cell::new("Transaction Type", bold),
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
                    BalanceChange::Incoming { value } => {
                        (value, change.fee_paid.to_coin(), "IN", green)
                    }
                    BalanceChange::Outgoing { value } => {
                        (value, change.fee_paid.to_coin(), "OUT", red)
                    }
                    BalanceChange::NoChange => {
                        (Coin::zero(), change.fee_paid.to_coin(), "NO CHANGE", blue)
                    }
                };

                rows.push(Row::new(vec![
                    Cell::new(&encode(&change.transaction_id), Default::default()),
                    Cell::new(in_out, format),
                    Cell::new(&amount, right_justify),
                    Cell::new(&format!("{}", fee), right_justify),
                    Cell::new(&change.transaction_type, Default::default()),
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

    fn resync<S: Storage, C: Client, O: TransactionObfuscation>(
        config: ObfuscationSyncerConfig<S, C, O>,
        name: String,
        enckey: SecKey,
        force: bool,
    ) -> Result<()> {
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
                        ..
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
                        ..
                    } => {
                        if let Some(ref mut pb) = progress_bar {
                            if current_block_height == final_block_height {
                                pb.finish_println("Synchronization complete!\n");
                            } else {
                                pb.set(current_block_height - init_block_height);
                            }
                        }
                    }
                }
            }
        });

        let syncer = WalletSyncer::with_obfuscation_config(config, Some(sender), name, enckey)?;
        if force {
            syncer.reset_state()?;
        }
        syncer.sync()?;
        std::mem::drop(syncer);
        let _ = handle.join();
        Ok(())
    }
}
