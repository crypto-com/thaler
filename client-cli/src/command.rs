mod address_command;
mod multisig_command;
mod transaction_command;
mod wallet_command;

use std::convert::TryInto;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Local, NaiveDateTime, Utc};
use cli_table::format::{CellFormat, Color, Justify};
use cli_table::{Cell, Row, Table};
use hex::encode;
#[cfg(feature = "mock-enclave")]
use log::warn;
use pbr::ProgressBar;
use quest::{ask, success};
use structopt::StructOpt;

use chain_core::init::coin::Coin;
use chain_core::state::account::{NodeState, StakedStateAddress};
use client_common::storage::SledStorage;
#[cfg(not(feature = "mock-enclave"))]
use client_common::tendermint::types::AbciQueryExt;
use client_common::tendermint::types::GenesisExt;
use client_common::tendermint::{Client, WebsocketRpcClient};
use client_common::TransactionObfuscation;
use client_common::{ErrorKind, Result, ResultExt, SecKey, Storage};
use client_core::signer::WalletSignerManager;
use client_core::transaction_builder::DefaultWalletTransactionBuilder;
use client_core::types::BalanceChange;
use client_core::wallet::syncer::{
    spawn_light_client_supervisor, Handle, ObfuscationSyncerConfig, ProgressReport, SyncerOptions,
    WalletSyncer,
};
use client_core::wallet::{DefaultWalletClient, WalletClient};
use client_network::network_ops::{DefaultNetworkOpsClient, NetworkOpsClient};

use self::address_command::AddressCommand;
use self::multisig_command::MultiSigCommand;
use self::transaction_command::TransactionCommand;
use self::wallet_command::WalletCommand;
use crate::logo::{get_jok, get_logo};
use crate::{ask_seckey, storage_path, tendermint_url};
use chain_core::tx::fee::LinearFee;
use client_core::hd_wallet::HardwareKind;
#[cfg(feature = "mock-hardware-wallet")]
use client_core::service::MockHardwareService;
use client_core::service::{HwKeyService, LedgerService, WalletService};
use once_cell::sync::Lazy;
use std::env;

#[cfg(feature = "mock-enclave")]
use client_common::cipher::mock::MockAbciTransactionObfuscation;
#[cfg(not(feature = "mock-enclave"))]
use client_common::cipher::DefaultTransactionObfuscation;

#[cfg(not(feature = "mock-enclave"))]
type AppTransactionCipher = DefaultTransactionObfuscation;
#[cfg(feature = "mock-enclave")]
type AppTransactionCipher = MockAbciTransactionObfuscation<WebsocketRpcClient>;

type AppTxBuilder = DefaultWalletTransactionBuilder<SledStorage, LinearFee, AppTransactionCipher>;
type AppWalletClient = DefaultWalletClient<SledStorage, WebsocketRpcClient, AppTxBuilder>;

static VERSION: Lazy<String> = Lazy::new(|| {
    format!(
        "{} {}:{}\n {}\n{}",
        env!("CARGO_PKG_VERSION"),
        env!("VERGEN_BUILD_DATE"),
        env!("VERGEN_SHA_SHORT"),
        get_logo(),
        get_jok(),
    )
});

#[cfg(feature = "mock-hardware-wallet")]
const HARDWARE_WALLET_KIND: [&str; 3] = ["ledger", "trezor", "mock"];

#[cfg(not(feature = "mock-hardware-wallet"))]
const HARDWARE_WALLET_KIND: [&str; 2] = ["ledger", "trezor"];

#[derive(Debug, StructOpt)]
#[structopt(
    name = "client-cli",
    version = VERSION.as_str(),
    about = r#"Basic CLI tool for interacting with Crypto.com Chain
ENVIRONMENT VARIABLES:
    CRYPTO_CLIENT_DEBUG             Set to `true` for detailed error messages (Default: `false`)
    CRYPTO_CHAIN_ID                 Chain ID of Crypto.com Chain
    CRYPTO_CLIENT_STORAGE           Storage directory (Default: `.storage`)
    CRYPTO_CLIENT_TENDERMINT        Websocket endpoint for tendermint (Default: `ws://localhost:26657/websocket`)
    CRYPTO_GENESIS_FINGERPRINT             Set the genesis fingerprint(Optional)
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
        #[structopt(name = "wallet name", short = "n", long = "name", help = "Wallet name")]
        name: String,
        #[structopt(
            name = "staking address",
            short = "a",
            long = "address",
            help = "Staking address"
        )]
        address: StakedStateAddress,
        #[structopt(
            name = "hardware wallet type",
            long = "hardware",
            help = "Hardware wallet type",
            possible_values = &HARDWARE_WALLET_KIND,
            case_insensitive = false
        )]
        hardware: Option<HardwareKind>,
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
            name = "enable-fast-forward",
            long,
            help = "Enable fast forward, which is not secure when connecting to outside nodes"
        )]
        enable_fast_forward: bool,
        #[structopt(
            name = "disable-light-client",
            long,
            help = "Disable light client, which is not secure when connecting to outside nodes"
        )]
        disable_light_client: bool,

        #[structopt(
            name = "light client peer",
            short = "l",
            long = "light-client-peers",
            help = "Light client peers"
        )]
        light_client_peers: Option<String>,

        #[structopt(
            name = "light client trusting period in seconds",
            long = "light-client-trusting-period",
            help = "light client trusting period in seconds"
        )]
        light_client_trusting_period_seconds: Option<u64>,

        #[structopt(
            name = "light client trusting height",
            long = "light-client-trusting-height",
            help = "light client trusting height"
        )]
        light_client_trusting_height: Option<u64>,

        #[structopt(
            name = "light client trusting blockhash",
            long = "light-client-trusting-blockhash",
            help = "light client trusting blockhash"
        )]
        light_client_trusting_blockhash: Option<String>,

        #[structopt(
            name = "disable-address-recovery",
            long,
            help = "Disable address recovery, which is not necessary, if addresses already exist"
        )]
        disable_address_recovery: bool,
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
#[cfg(not(feature = "mock-enclave"))]
fn get_tx_query(tendermint_client: WebsocketRpcClient) -> Result<DefaultTransactionObfuscation> {
    let result = tendermint_client
        .query("txquery", &[], None, false)?
        .bytes();
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

/// mock
#[cfg(feature = "mock-enclave")]
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
                let wallet_name = transaction_command.wallet_name();
                let wallet_service = WalletService::new(storage.clone());
                let enckey = ask_seckey(None)?;
                let wallet = wallet_service.get_wallet(&wallet_name, &enckey)?;
                let hw_key_service = match wallet.hardware_kind {
                    #[cfg(feature = "mock-hardware-wallet")]
                    HardwareKind::Mock => HwKeyService::Mock(MockHardwareService::new()),
                    HardwareKind::Trezor => HwKeyService::default(),
                    HardwareKind::Ledger => {
                        let ledger_service = LedgerService::new(true)?;
                        HwKeyService::Ledger(ledger_service)
                    }
                    HardwareKind::LocalOnly => HwKeyService::default(),
                };
                let signer_manager =
                    WalletSignerManager::new(storage.clone(), hw_key_service.clone());
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
                    hw_key_service,
                );
                let network_ops_client = DefaultNetworkOpsClient::new(
                    wallet_client,
                    signer_manager,
                    tendermint_client,
                    fee_algorithm,
                    transaction_obfuscation,
                );
                transaction_command.execute(
                    network_ops_client.get_wallet_client(),
                    &network_ops_client,
                    enckey,
                )
            }
            Command::StakedState {
                name,
                address,
                hardware,
            } => {
                let hw_key_service = match hardware {
                    None => HwKeyService::default(),
                    #[cfg(feature = "mock-hardware-wallet")]
                    Some(HardwareKind::Mock) => HwKeyService::Mock(MockHardwareService::new()),
                    Some(HardwareKind::Trezor) => HwKeyService::default(),
                    Some(HardwareKind::Ledger) => {
                        let ledger_service = LedgerService::new(true)?;
                        HwKeyService::Ledger(ledger_service)
                    }
                    Some(HardwareKind::LocalOnly) => HwKeyService::default(),
                };
                let storage = SledStorage::new(storage_path())?;
                let tendermint_client = WebsocketRpcClient::new(&tendermint_url())?;
                let signer_manager =
                    WalletSignerManager::new(storage.clone(), hw_key_service.clone());
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
                    hw_key_service,
                );

                let network_ops_client = DefaultNetworkOpsClient::new(
                    wallet_client,
                    signer_manager,
                    tendermint_client,
                    fee_algorithm,
                    transaction_obfuscation,
                );
                Self::get_staked_stake(&network_ops_client, &name, address)
            }
            Command::Sync {
                name,
                batch_size,
                force,
                enable_fast_forward,
                disable_light_client,
                disable_address_recovery,
                block_height_ensure,
                light_client_peers,
                light_client_trusting_period_seconds,
                light_client_trusting_height,
                light_client_trusting_blockhash,
            } => {
                let rpc_url = tendermint_url();
                let tendermint_client = WebsocketRpcClient::new(&rpc_url)?;
                let tx_obfuscation = get_tx_query(tendermint_client.clone())?;
                let db_path = storage_path();
                let storage = SledStorage::new(&db_path)?;
                let max_trusting_period = tendermint_client.genesis()?.trusting_period() / 2;

                let mut light_client_peers_user: String = "".into();
                let mut light_client_trusting_period_seconds_user: u64 = 0;
                let mut light_client_trusting_height_user: u64 = 0;
                let mut light_client_trusting_blockhash_user: String = "".into();
                let mut automode = false;

                if !disable_light_client {
                    light_client_peers_user = if let Some(value) = light_client_peers {
                        value.clone()
                    } else {
                        ask("Enter light-client peers (node@ip:port,node1@ip:port): ");
                        quest::text().chain(|| {
                            (
                                ErrorKind::IoError,
                                "Unable to read value  light-client-peers",
                            )
                        })?
                    };

                    light_client_trusting_period_seconds_user = if let Some(value) =
                        light_client_trusting_period_seconds
                    {
                        *value
                    } else {
                        success(format!("Light-client trusting period should be smaller than {:?}\nFor the safety, check the time carefully.",max_trusting_period).as_str());
                        ask("Enter light-client trusting period (in seconds): ");
                        let value_str = quest::text().chain(|| {
                            (ErrorKind::IoError, "Unable to read value  trusting period")
                        })?;
                        value_str.parse::<u64>().chain(|| {
                            (ErrorKind::IoError, "Unable to parse value  trusting period")
                        })?
                    };

                    light_client_trusting_height_user =
                        if let Some(value) = light_client_trusting_height {
                            *value
                        } else {
                            ask("Enter light-client trusting height: ");
                            let value_str = quest::text().chain(|| {
                                (ErrorKind::IoError, "Unable to read value trusting height")
                            })?;
                            value_str.parse::<u64>().chain(|| {
                                (ErrorKind::IoError, "Unable to parse value trusting height")
                            })?
                        };

                    light_client_trusting_blockhash_user = if let Some(value) =
                        light_client_trusting_blockhash
                    {
                        if "" == value {
                            automode = true;
                        }
                        value.clone()
                    } else {
                        ask("You can find specific block-hash in block-explorer.\nIf you don't have it, just press return-key\nEnter light-client trusting block-hash: ");
                        quest::text().chain(|| {
                            (
                                ErrorKind::IoError,
                                "Unable to read value trusting block-hash",
                            )
                        })?
                    };

                    log::info!(
                        "light client options  trust peroid {} seconds    height={} blockhash={}",
                        light_client_trusting_period_seconds_user,
                        light_client_trusting_height_user,
                        light_client_trusting_blockhash_user
                    );
                }
                let enckey = ask_seckey(None)?;

                let mut trusting_period = max_trusting_period;
                if 0 < light_client_trusting_period_seconds_user {
                    trusting_period =
                        std::time::Duration::from_secs(light_client_trusting_period_seconds_user);
                }
                log::info!(
                    "light-client trusting period in seconds {:?}  height {}  blockhash {}",
                    trusting_period,
                    light_client_trusting_height_user,
                    light_client_trusting_blockhash_user,
                );

                let user_func = |number: u64, info: String| -> bool {
                    quest::ask(
                        format!(
                            "Height={}  BlockHash={} Would you confirm this block?(y or n)",
                            number, info
                        )
                        .as_str(),
                    );
                    quest::yesno(true)
                        .expect("get trusted block confirm")
                        .expect("get trusted block confirm")
                };

                let handle = if automode && !disable_light_client {
                    Some(spawn_light_client_supervisor(
                        db_path.as_ref(),
                        trusting_period,
                        light_client_peers_user.clone(),
                        light_client_trusting_period_seconds_user,
                        light_client_trusting_height_user,
                        "".into(),
                        None,
                    )?)
                } else if !automode && !disable_light_client {
                    Some(spawn_light_client_supervisor(
                        db_path.as_ref(),
                        trusting_period,
                        light_client_peers_user.clone(),
                        light_client_trusting_period_seconds_user,
                        light_client_trusting_height_user,
                        light_client_trusting_blockhash_user.clone(),
                        Some(Arc::new(Mutex::new(Box::new(user_func)))),
                    )?)
                } else {
                    None
                };

                let config = ObfuscationSyncerConfig::new(
                    storage.clone(),
                    tendermint_client,
                    tx_obfuscation,
                    SyncerOptions {
                        enable_fast_forward: *enable_fast_forward,
                        disable_light_client: *disable_light_client,
                        enable_address_recovery: !*disable_address_recovery,
                        batch_size: *batch_size,
                        block_height_ensure: *block_height_ensure,
                        light_client_peers: light_client_peers_user,
                        light_client_trusting_period_seconds:
                            light_client_trusting_period_seconds_user,
                        light_client_trusting_height: light_client_trusting_height_user,
                        light_client_trusting_blockhash: light_client_trusting_blockhash_user,
                    },
                    handle.clone(),
                );
                Self::resync(config, name.clone(), enckey, *force, storage)?;
                if let Some(this_handle) = handle.as_ref() {
                    this_handle
                        .terminate()
                        .expect("terminate light client supervisor in client-cli");
                }
                Ok(())
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
        let staked_state = network_ops_client.get_staked_state(name, address, true)?;

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
                    staked_state
                        .node_meta
                        .and_then(|val| match val {
                            NodeState::CommunityNode(_) => unreachable!("FIXME"),
                            NodeState::CouncilNode(v) => v.jailed_until,
                        })
                        .map_or_else(
                            || Cell::new("Not jailed", justify_right),
                            |jailed_until| {
                                Cell::new(
                                    &<DateTime<Local>>::from(DateTime::<Utc>::from_utc(
                                        NaiveDateTime::from_timestamp(
                                            jailed_until.try_into().unwrap(),
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
                    Cell::new("Last Slash Type", bold),
                    staked_state.last_slash.as_ref().map_or_else(
                        || Cell::new("Not slashed", justify_right),
                        |slash| Cell::new(&slash.kind.to_string(), justify_right),
                    ),
                ]),
                Row::new(vec![
                    Cell::new("Last Slash Amount", bold),
                    staked_state.last_slash.as_ref().map_or_else(
                        || Cell::new("Not slashed", justify_right),
                        |slash| Cell::new(&slash.amount, justify_right),
                    ),
                ]),
                Row::new(vec![
                    Cell::new("Last Slash Time", bold),
                    staked_state.last_slash.as_ref().map_or_else(
                        || Cell::new("Not slashed", justify_right),
                        |slash| {
                            Cell::new(
                                &<DateTime<Local>>::from(DateTime::<Utc>::from_utc(
                                    NaiveDateTime::from_timestamp(
                                        slash.time.try_into().unwrap(),
                                        0,
                                    ),
                                    Utc,
                                )),
                                justify_right,
                            )
                        },
                    ),
                ]),
            ],
            Default::default(),
        )
        .chain(|| (ErrorKind::InternalError, "Unable to create new table"))?;

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
        print_sync_warning();

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

        let table = Table::new(rows, Default::default())
            .chain(|| (ErrorKind::InternalError, "Unable to create new table"))?;
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
        print_sync_warning();

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

            let table = Table::new(rows, Default::default())
                .chain(|| (ErrorKind::InternalError, "Unable to create new table"))?;

            table
                .print_stdout()
                .chain(|| (ErrorKind::IoError, "Unable to print table"))?;
        } else {
            success("No history found!")
        }

        Ok(())
    }

    fn resync<S: Storage, C: Client, O: TransactionObfuscation, L: Handle + Send + Sync + Clone>(
        config: ObfuscationSyncerConfig<S, C, O, L>,
        name: String,
        enckey: SecKey,
        force: bool,
        storage: SledStorage,
    ) -> Result<()> {
        let wallet_client = get_wallet_client(storage)?;

        let mut init_block_height = 0;
        let mut final_block_height = 0;
        let mut progress_bar = None;
        let progress_callback = move |report| {
            match report {
                ProgressReport::Init {
                    start_block_height,
                    finish_block_height,
                    ..
                } => {
                    init_block_height = start_block_height;
                    final_block_height = finish_block_height;
                    progress_bar = Some(ProgressBar::new(finish_block_height - start_block_height));

                    let pb = progress_bar.as_mut().unwrap();
                    pb.message("Synchronizing: ");
                }
                ProgressReport::Update {
                    current_block_height,
                    ..
                } => {
                    if let Some(ref mut pb) = progress_bar {
                        if current_block_height == final_block_height {
                            pb.finish_print("Synchronization complete!");
                        } else {
                            pb.set(current_block_height - init_block_height);
                        }
                    }
                }
            };
            true
        };

        let mut syncer =
            WalletSyncer::with_obfuscation_config(config, name, enckey, wallet_client)?;
        if force {
            syncer.reset_state()?;
        }
        syncer.sync(progress_callback)
    }
}

fn print_sync_warning() {
    ask("Warning! Information displayed here may be outdated. To get the latest information, do `client-cli sync --name <wallet name>`");
    println!();
}

fn get_wallet_client(storage: SledStorage) -> Result<AppWalletClient> {
    let tendermint_client = WebsocketRpcClient::new(&tendermint_url())?;

    let hw_key_service = HwKeyService::default();

    let signer_manager = WalletSignerManager::new(storage.clone(), hw_key_service.clone());
    let fee_algorithm = tendermint_client.genesis()?.fee_policy();
    let transaction_obfuscation = get_tx_query(tendermint_client.clone())?;
    let transaction_builder = DefaultWalletTransactionBuilder::new(
        signer_manager,
        fee_algorithm,
        transaction_obfuscation,
    );

    let wallet_client = DefaultWalletClient::new(
        storage,
        tendermint_client,
        transaction_builder,
        None,
        hw_key_service,
    );
    Ok(wallet_client)
}
