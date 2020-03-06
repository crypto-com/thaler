use jsonrpc_core::IoHandler;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use chain_core::tx::fee::LinearFee;
use client_common::storage::SledStorage;
use client_common::tendermint::{types::GenesisExt, Client, WebsocketRpcClient};
use client_common::{ErrorKind, Result, ResultExt};
#[cfg(not(feature = "mock-enc-dec"))]
use client_core::cipher::DefaultTransactionObfuscation;
#[cfg(feature = "mock-enc-dec")]
use client_core::cipher::MockAbciTransactionObfuscation;
use client_core::signer::WalletSignerManager;
use client_core::transaction_builder::DefaultWalletTransactionBuilder;
use client_core::wallet::syncer::ObfuscationSyncerConfig;
use client_core::wallet::DefaultWalletClient;
use client_network::network_ops::DefaultNetworkOpsClient;
use client_rpc::rpc::{
    multisig_rpc::{MultiSigRpc, MultiSigRpcImpl},
    staking_rpc::{StakingRpc, StakingRpcImpl},
    sync_rpc::{SyncRpc, SyncRpcImpl},
    transaction_rpc::{TransactionRpc, TransactionRpcImpl},
    wallet_rpc::{WalletRpc, WalletRpcImpl},
};

use crate::types::CroResult;
use crate::types::ProgressCallback;
use client_rpc::rpc::sync_rpc::{CBindingCallback, CBindingCore};

#[cfg(not(feature = "mock-enc-dec"))]
type AppTransactionCipher = DefaultTransactionObfuscation;
#[cfg(feature = "mock-enc-dec")]
type AppTransactionCipher = MockAbciTransactionObfuscation<WebsocketRpcClient>;

type AppTxBuilder = DefaultWalletTransactionBuilder<SledStorage, LinearFee, AppTransactionCipher>;
type AppWalletClient = DefaultWalletClient<SledStorage, WebsocketRpcClient, AppTxBuilder>;
type AppOpsClient = DefaultNetworkOpsClient<
    AppWalletClient,
    SledStorage,
    WebsocketRpcClient,
    LinearFee,
    AppTransactionCipher,
>;
type AppSyncerConfig =
    ObfuscationSyncerConfig<SledStorage, WebsocketRpcClient, AppTransactionCipher>;

/// normal
#[cfg(not(feature = "mock-enc-dec"))]
fn get_tx_query(tendermint_client: WebsocketRpcClient) -> Result<DefaultTransactionObfuscation> {
    DefaultTransactionObfuscation::from_tx_query(&tendermint_client)
}

/// temporary
#[cfg(feature = "mock-enc-dec")]
fn get_tx_query(
    tendermint_client: WebsocketRpcClient,
) -> Result<MockAbciTransactionObfuscation<WebsocketRpcClient>> {
    Ok(MockAbciTransactionObfuscation::new(tendermint_client))
}

fn make_wallet_client(
    storage: SledStorage,
    tendermint_client: WebsocketRpcClient,
) -> Result<AppWalletClient> {
    let signer_manager = WalletSignerManager::new(storage.clone());
    let transaction_cipher = get_tx_query(tendermint_client.clone())?;
    let transaction_builder = DefaultWalletTransactionBuilder::new(
        signer_manager,
        tendermint_client.genesis().unwrap().fee_policy(),
        transaction_cipher,
    );
    Ok(DefaultWalletClient::new(
        storage,
        tendermint_client,
        transaction_builder,
        Some(50),
    ))
}

fn make_ops_client(
    storage: SledStorage,
    tendermint_client: WebsocketRpcClient,
) -> Result<AppOpsClient> {
    let transaction_cipher = get_tx_query(tendermint_client.clone())?;
    let signer_manager = WalletSignerManager::new(storage.clone());
    let fee_algorithm = tendermint_client.genesis().unwrap().fee_policy();
    let wallet_client = make_wallet_client(storage, tendermint_client.clone())?;
    Ok(DefaultNetworkOpsClient::new(
        wallet_client,
        signer_manager,
        tendermint_client,
        fee_algorithm,
        transaction_cipher,
    ))
}

fn make_syncer_config(
    storage: SledStorage,
    tendermint_client: WebsocketRpcClient,
) -> Result<AppSyncerConfig> {
    let transaction_cipher = get_tx_query(tendermint_client.clone())?;

    Ok(AppSyncerConfig::new(
        storage,
        tendermint_client,
        transaction_cipher,
        true,
        50,
        50,
    ))
}

use std::sync::Arc;
use std::sync::Mutex;

#[derive(Clone)]
struct CBindingData {
    progress_callback: ProgressCallback,
    user_data: u64,
}

impl CBindingCallback for CBindingData {
    fn set_user(&mut self, user: u64) {
        self.user_data = user;
    }
    fn get_user(&self) -> u64 {
        self.user_data
    }

    fn progress(&self, current: u64, start: u64, end: u64) -> i32 {
        let back = &self.progress_callback;
        (back)(
            current,
            start,
            end,
            self.user_data as *const std::ffi::c_void,
        )
    }
}

fn do_jsonrpc_call(
    storage_dir: &str,
    websocket_url: &str,
    network_id: u8,
    json_request: &str,
    progress_callback: ProgressCallback,
    user_data: *const std::ffi::c_void,
) -> Result<String> {
    let mut io = IoHandler::new();
    let storage = SledStorage::new(storage_dir)?;
    let tendermint_client = WebsocketRpcClient::new(websocket_url)?;
    let wallet_client = make_wallet_client(storage.clone(), tendermint_client.clone())?;
    let ops_client = make_ops_client(storage.clone(), tendermint_client.clone())?;
    let syncer_config = make_syncer_config(storage, tendermint_client)?;

    let multisig_rpc = MultiSigRpcImpl::new(wallet_client.clone());
    let transaction_rpc = TransactionRpcImpl::new(network_id);
    let staking_rpc = StakingRpcImpl::new(wallet_client.clone(), ops_client, network_id);
    let cbindingcallback = CBindingCore {
        data: Arc::new(Mutex::new(CBindingData {
            progress_callback,
            user_data: user_data as u64,
        })),
    };
    let sync_rpc = SyncRpcImpl::new(syncer_config, Some(cbindingcallback));
    let wallet_rpc = WalletRpcImpl::new(wallet_client, network_id);

    io.extend_with(multisig_rpc.to_delegate());
    io.extend_with(transaction_rpc.to_delegate());
    io.extend_with(staking_rpc.to_delegate());
    io.extend_with(sync_rpc.to_delegate());
    io.extend_with(wallet_rpc.to_delegate());

    // let request = r#"{"jsonrpc": "2.0", "method": "say_hello", "params": [42, 23], "id": 1}"#;
    io.handle_request_sync(json_request)
        .err_kind(ErrorKind::InvalidInput, || {
            "stateful command execute failed"
        })
}

/// # Safety
///
/// Should not be called with null pointers.
///
/// c example:
///
/// ```c
/// char buf[BUFSIZE];
/// const char* req = "{\"jsonrpc\": \"2.0\", \"method\": \"wallet_list\", \"params\": [], \"id\": 1}";
/// int retcode = cro_jsonrpc_call("./data", "ws://...", 0xab, req, buf, sizeof(buf));
/// if (retcode == 0) {
///     printf("response: %s\n", buf);
/// } else {
///     printf("error: %s\n", buf);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn cro_jsonrpc_call(
    storage_dir: *const c_char,
    websocket_url: *const c_char,
    network_id: u8,
    request: *const c_char,
    buf: *mut c_char,
    buf_size: usize,
    progress_callback: ProgressCallback,
    user_data: *const std::ffi::c_void,
) -> CroResult {
    let res = do_jsonrpc_call(
        CStr::from_ptr(storage_dir)
            .to_str()
            .expect("storage_dir should be utf-8"),
        CStr::from_ptr(websocket_url)
            .to_str()
            .expect("storage_dir should be utf-8"),
        network_id,
        CStr::from_ptr(request)
            .to_str()
            .expect("storage_dir should be utf-8"),
        progress_callback,
        user_data,
    );
    match res {
        Err(e) => {
            libc::strncpy(
                buf,
                CString::new(e.to_string()).unwrap().into_raw(),
                buf_size,
            );
            CroResult::fail()
        }
        Ok(s) => {
            libc::strncpy(buf, CString::new(s).unwrap().into_raw(), buf_size);
            CroResult::success()
        }
    }
}
