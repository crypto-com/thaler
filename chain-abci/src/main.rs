use chain_abci::app::{sanity_check_enabled, ChainNodeApp};
#[cfg(all(not(feature = "mock-enclave"), feature = "edp", target_os = "linux"))]
use chain_abci::enclave_bridge::edp::{
    launch_tx_validation, temp_start_up_ra_tx_query, TempTxQueryOptions, TxValidationApp,
};
#[cfg(any(feature = "mock-enclave", not(target_os = "linux")))]
use chain_abci::enclave_bridge::mock::MockClient;
use chain_abci::enclave_bridge::EnclaveProxy;
use chain_core::init::network::{get_network, get_network_id, init_chain_id};
use chain_storage::ReadOnlyStorage;
use chain_storage::{Storage, StorageConfig, StorageType};
use log::{error, info, warn};
use ra_sp_server::config::SpRaConfig;
use serde::{Deserialize, Serialize};
use std::env::var;
use std::fs::{create_dir_all, write, File};
use std::io::BufReader;
use std::net::SocketAddr;
#[cfg(all(not(feature = "mock-enclave"), feature = "edp", target_os = "linux"))]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

/// TODO: should this also set the tx-query enclave file path
/// or just assume (as with tx-validation), its SGXS/SIG are in the same directory
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    port: u16,
    host: String,
    genesis_app_hash: String,
    chain_id: String,
    tx_query: Option<String>,
    // if different from `tx_query`
    tx_query_listen: Option<String>,
    launch_ra_proxy: bool,
    remote_attestation: SpRaConfig,
    data_bootstrap: TdbeConfig,
}

/// TODO: more concrete when ready
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TdbeConfig {
    /// Optional TM RPC address of another TDBE server from where to fetch data
    /// TODO: it'll get txids + the TDBE connection details from RPC
    /// TODO: DNS can be obtained from RPC?
    pub remote_rpc_address: Option<String>,
    /// TODO: expose on RPC / query?
    pub local_addresse: String,
    /// TDBE server address to listen on E.g. `0.0.0.0:3445`
    /// set to something if different from local_address
    pub local_listen_address: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 26658,
            host: "127.0.0.1".into(),
            genesis_app_hash: "54F4F05167492B83F0135AA55D27308C43AEA36E3FE91F4AD21028728207D70F"
                .into(),
            chain_id: "testnet-thaler-crypto-com-chain-42".into(),
            tx_query: None,
            tx_query_listen: None,
            // in multi-node integration tests, the proxy is shared among nodes
            launch_ra_proxy: false,
            remote_attestation: SpRaConfig {
                // TODO: this is probably not necessary if chain-abci is the launcher
                // (it can just open some local unix domain socket and provide it via usercall extension)
                address: "127.0.0.1:8989".into(),
                ias_key: var("IAS_KEY").unwrap_or_else(|_| "".into()),
                spid: var("SPID").unwrap_or_else(|_| "".into()),
                // TODO: should this be fixed "Unlinkable"?
                quote_type: "Unlinkable".into(),
                // TODO: should this be compile-time? also the enclave should verify
                ias_base_uri: "https://api.trustedservices.intel.com/sgx/dev".into(),
                // TODO: compile-time? only needed to change with version upgrades
                ias_sig_rl_path: "/attestation/v4/sigrl/".into(),
                // TODO: compile-time? only needed to change with version upgrades
                ias_report_path: "/attestation/v4/report".into(),
            },
            data_bootstrap: TdbeConfig::default(),
        }
    }
}

impl Config {
    pub fn from_file(path: &Path) -> Self {
        let file =
            File::open(path).unwrap_or_else(|_| panic!("can not open config file {:?}", path));
        let reader = BufReader::new(file);
        serde_yaml::from_reader(reader).expect("invalid config")
    }
    pub fn update(&mut self, opt: &AbciOpt) {
        if opt.host.is_some() {
            self.host = opt.host.clone().unwrap();
        }
        if opt.port.is_some() {
            self.port = opt.port.unwrap();
        }
        if let Some(gah) = opt.genesis_app_hash.as_ref() {
            self.genesis_app_hash = gah.clone();
        }
        if let Some(cid) = opt.chain_id.as_ref() {
            self.chain_id = cid.clone();
        }
        if opt.enclave_server.is_some() {
            warn!("enclave_server is deprecated");
        }
        if opt.tx_query.is_some() {
            self.tx_query = opt.tx_query.clone();
        }
    }
    pub fn is_valid(&self) -> bool {
        let mut valid = true;
        if self.genesis_app_hash.is_empty() {
            error!("genesis_app_hash should be set");
            valid = false
        }
        if self.chain_id.is_empty() {
            error!("chain_id should be set");
            valid = false
        }
        valid
    }
}

/// Enum used to specify top-level chain-abci commands
#[derive(Debug, StructOpt)]
#[structopt(
    name = "chain-abci",
    about = "Crypto.com Chain node (Tendermint ABCI application)."
)]
pub enum AbciApp {
    /// Run chain-abci
    #[structopt(name = "run", about = "start up the chain-abci process")]
    Run {
        #[structopt(flatten)]
        run_command: AbciOpt,
    },

    /// Used for initializing the configuration file
    #[structopt(
        name = "init",
        about = "Initialize the configuration file in the data directory"
    )]
    Init {
        #[structopt(
            short = "d",
            long = "data",
            default_value = ".cro-storage/",
            help = "Sets a data storage directory"
        )]
        data: String,
    },
}

#[derive(Debug, StructOpt)]
pub struct AbciOpt {
    #[structopt(
        short = "d",
        long = "data",
        default_value = ".cro-storage/",
        help = "Sets a data storage directory"
    )]
    data: String,
    #[structopt(short = "p", long = "port", help = "Sets a port to listen on")]
    port: Option<u16>,
    #[structopt(short = "h", long = "host", help = "Sets the ip address to listen on")]
    host: Option<String>,
    #[structopt(
        short = "g",
        long = "genesis_app_hash",
        help = "The expected app hash after init chain (computed from the merkle trie root etc.)"
    )]
    genesis_app_hash: Option<String>,
    #[structopt(
        short = "c",
        long = "chain_id",
        help = "The expected chain id from init chain (the name convention is \"...some-name...-<TWO_HEX_DIGITS>\")"
    )]
    chain_id: Option<String>,
    #[structopt(short = "e", long = "enclave_server", help = "DEPRECATED")]
    enclave_server: Option<String>,
    #[structopt(
        short = "tq",
        long = "tx_query",
        help = "Optional transaction query support for clients (tx query enclave listening address, e.g. mydomain.com:4444)"
    )]
    tx_query: Option<String>,
}

/// edp
#[cfg(all(not(feature = "mock-enclave"), feature = "edp", target_os = "linux"))]
fn get_enclave_proxy() -> TxValidationApp {
    launch_tx_validation()
}

/// for development
#[cfg(any(feature = "mock-enclave", not(target_os = "linux")))]
fn get_enclave_proxy() -> MockClient {
    warn!("Using mock (non-enclave) infrastructure");
    MockClient::new(get_network_id())
}

/// edp
#[cfg(all(not(feature = "mock-enclave"), feature = "edp", target_os = "linux"))]
fn start_up_ra_tx_query<T: EnclaveProxy + 'static>(
    config: &Config,
    proxy: T,
    storage: ReadOnlyStorage,
) {
    if let Some(tx_query_address) = config.tx_query.as_ref() {
        let (sender, receiver) = UnixStream::pair().expect("init tx query socket");
        let network_id = hex::decode(&config.chain_id[config.chain_id.len() - 2..])
            .expect("failed to decode two last hex digits in chain ID")[0];
        let tqe_address = if let Some(listen_addr) = config.tx_query_listen.as_ref() {
            listen_addr.clone()
        } else {
            tx_query_address.clone()
        };
        temp_start_up_ra_tx_query(
            if config.launch_ra_proxy {
                Some(config.remote_attestation.clone())
            } else {
                None
            },
            TempTxQueryOptions {
                chain_abci_data: sender,
                sp_address: config.remote_attestation.address.clone(),
                address: tqe_address,
            },
            proxy,
            network_id,
            storage,
            receiver,
        );
    }
}

/// for development
#[cfg(any(feature = "mock-enclave", not(target_os = "linux")))]
fn start_up_ra_tx_query<T: EnclaveProxy + 'static>(
    _config: &Config,
    _proxy: T,
    _storage: ReadOnlyStorage,
) {
    // nothing
}

fn main() {
    env_logger::init();
    let app_command = AbciApp::from_args();
    match app_command {
        AbciApp::Init { data } => {
            let mut config_file = PathBuf::from(&data);
            config_file.push("config.yaml");
            if config_file.exists() {
                warn!("{} already exists", config_file.display());
            } else {
                let config = Config::default();
                let config_payload =
                    serde_yaml::to_string(&config).expect("failed to serialize config");
                info!("writing {}", &config_file.display());
                if create_dir_all(data).is_err() {
                    warn!("failed to create data directory");
                }
                if write(config_file, config_payload).is_err() {
                    error!("failed to write configuration");
                } else {
                    info!("please adjust the configuration as needed");
                }
            };
        }
        AbciApp::Run { run_command } => {
            let opt = run_command;
            // use DATA_PATH/config.yaml as default
            let mut config_file = PathBuf::from(&opt.data);
            config_file.push("config.yaml");
            let mut config = if config_file.exists() {
                Config::from_file(config_file.as_path())
            } else {
                Config::default()
            };
            config.update(&opt);
            if !config.is_valid() {
                return;
            }

            init_chain_id(&config.chain_id);
            info!(
                "network={:?} network_id={:X}",
                get_network(),
                get_network_id()
            );
            let tx_validator = get_enclave_proxy();
            if sanity_check_enabled() {
                warn!("Enabled sanity checks");
            }

            let host = config.host.parse().expect("invalid host");
            let addr = SocketAddr::new(host, config.port);
            let storage = Storage::new(&StorageConfig::new(&opt.data, StorageType::Node));
            start_up_ra_tx_query(&config, tx_validator.clone(), storage.get_read_only());
            info!("starting up");
            abci::run(
                addr,
                ChainNodeApp::new_with_storage(
                    tx_validator,
                    &config.genesis_app_hash,
                    &config.chain_id,
                    storage,
                    config.tx_query,
                ),
            );
        }
    }
}
