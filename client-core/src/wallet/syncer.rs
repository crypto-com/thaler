#![allow(missing_docs)]
use indexmap::IndexMap;
use itertools::{izip, Itertools};
use std::cmp::{max, Ordering};
use std::collections::HashMap;
use std::iter;
use std::path::Path;
use std::result;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
pub use tendermint_light_client::supervisor::Handle;
use tendermint_light_client::{
    components::{
        clock::SystemClock,
        io::{AtHeight, Io, ProdIo},
        scheduler,
        verifier::ProdVerifier,
    },
    evidence::ProdEvidenceReporter,
    fork_detector::ProdForkDetector,
    light_client::{self, LightClient},
    operations::hasher::{Hasher, ProdHasher},
    peer_list::PeerList,
    state::State,
    store::{sled::SledStore, LightStore},
    supervisor::{Instance, Supervisor},
    types::{LightBlock, PeerId, Status, TrustThreshold},
};

use chain_core::common::H256;
use chain_core::state::account::StakedStateAddress;
use chain_core::state::ChainState;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_core::tx::TransactionId;
use chain_storage::jellyfish::compute_staking_root;
use chain_tx_filter::BlockFilter;
use chain_util::NonEmpty;
use client_common::tendermint::types::{
    Block, BlockExt, BlockResults, BlockResultsResponse, Genesis, Time,
};
use client_common::tendermint::Client;
use client_common::{
    Error, ErrorKind, PrivateKey, Result, ResultExt, SecKey, SecureStorage, Transaction,
    TransactionObfuscation,
};

use super::syncer_logic::handle_blocks;
use crate::service;
use crate::service::{KeyService, SyncState, Wallet, WalletState, WalletStateMemento};

pub trait LightClientHandle: Handle + Send + Sync + Clone {}
impl<T: Handle + Send + Sync + Clone> LightClientHandle for T {}

pub trait AddressRecovery: Clone + Send + Sync {
    // new_address: transfer address in TxOut
    // return: true, new addresses are generated
    fn recover_addresses(
        &mut self,
        new_address: &ExtendedAddr,
        name: &str,
        enckey: &SecKey,
        wallet: &mut Wallet,
    ) -> Result<bool>;
}

/// Transaction decryptor interface for wallet synchronizer
pub trait TxDecryptor: Clone + Send + Sync {
    /// decrypt transaction
    fn decrypt_tx(&self, txids: &[TxId]) -> Result<Vec<Transaction>>;
}

impl<F> TxDecryptor for F
where
    F: Fn(&[TxId]) -> Result<Vec<Transaction>> + Clone + Send + Sync,
{
    fn decrypt_tx(&self, txids: &[TxId]) -> Result<Vec<Transaction>> {
        self(txids)
    }
}

/// Load view key and decrypt transaction with `TransactionObfuscation` and `KeyService`
#[derive(Clone)]
pub struct TxObfuscationDecryptor<O: TransactionObfuscation> {
    obfuscation: O,
    private_key: PrivateKey,
}

impl<O: TransactionObfuscation> TxObfuscationDecryptor<O> {
    /// Construct TxObfuscationDecryptor for a wallet
    pub fn new(obfuscation: O, private_key: PrivateKey) -> TxObfuscationDecryptor<O> {
        TxObfuscationDecryptor {
            obfuscation,
            private_key,
        }
    }
}

impl<O: TransactionObfuscation> TxDecryptor for TxObfuscationDecryptor<O> {
    fn decrypt_tx(&self, txids: &[TxId]) -> Result<Vec<Transaction>> {
        self.obfuscation.decrypt(&txids, &self.private_key)
    }
}

/// Configuration options for synchronizer
#[derive(Clone, Debug)]
pub struct SyncerOptions {
    pub enable_fast_forward: bool,
    pub enable_address_recovery: bool,
    pub batch_size: usize,
    pub block_height_ensure: u64,
}

/// Common configs for wallet syncer with `TransactionObfuscation`
#[derive(Clone)]
pub struct ObfuscationSyncerConfig<
    S: SecureStorage,
    C: Client,
    O: TransactionObfuscation,
    L: LightClientHandle,
> {
    // services
    pub storage: S,
    pub client: C,
    pub obfuscation: O,
    pub light_client: L,

    // configs
    pub options: SyncerOptions,
}

impl<S: SecureStorage, C: Client, O: TransactionObfuscation, L: LightClientHandle>
    ObfuscationSyncerConfig<S, C, O, L>
{
    /// Construct ObfuscationSyncerConfig
    pub fn new(
        storage: S,
        client: C,
        obfuscation: O,
        options: SyncerOptions,
        light_client: L,
    ) -> ObfuscationSyncerConfig<S, C, O, L> {
        ObfuscationSyncerConfig {
            storage,
            client,
            obfuscation,
            options,
            light_client,
        }
    }
}

/// Common configs for wallet syncer
#[derive(Clone)]
pub struct SyncerConfig<S: SecureStorage, C: Client, L: LightClientHandle> {
    // services
    storage: S,
    client: C,
    light_client: L,

    // configs
    options: SyncerOptions,
}

/// Wallet Syncer
#[derive(Clone)]
pub struct WalletSyncer<
    S: SecureStorage,
    C: Client,
    D: TxDecryptor,
    T: AddressRecovery,
    L: LightClientHandle,
> {
    // common
    storage: S,
    client: C,
    recover_address: T,
    options: SyncerOptions,

    // wallet
    decryptor: D,
    name: String,
    enckey: SecKey,
    light_client: L,
}

impl<S, C, D, T, L> WalletSyncer<S, C, D, T, L>
where
    S: SecureStorage,
    C: Client,
    D: TxDecryptor,
    T: AddressRecovery,
    L: LightClientHandle,
{
    /// Construct with common config
    pub fn with_config(
        config: SyncerConfig<S, C, L>,
        decryptor: D,
        name: String,
        enckey: SecKey,
        recover_address: T,
    ) -> WalletSyncer<S, C, D, T, L> {
        Self {
            storage: config.storage,
            client: config.client,
            decryptor,
            name,
            enckey,
            options: config.options,
            recover_address,
            light_client: config.light_client,
        }
    }

    /// Delete sync state and wallet state.
    pub fn reset_state(&self) -> Result<()> {
        service::delete_sync_state(&self.storage, &self.name)?;
        service::delete_wallet_state(&self.storage, &self.name)?;
        Ok(())
    }

    /// Load wallet state in memory, sync it to most recent latest, then drop the memory cache.
    pub fn sync<F: FnMut(ProgressReport) -> bool>(&mut self, callback: F) -> Result<()> {
        WalletSyncerImpl::new(self, callback)?.sync()
    }
}

fn load_view_key<S: SecureStorage>(storage: &S, name: &str, enckey: &SecKey) -> Result<PrivateKey> {
    KeyService::new(storage.clone())
        .wallet_private_key(name, enckey)?
        .err_kind(ErrorKind::InvalidInput, || {
            format!("wallet private view key not found: {}", name)
        })
}

impl<S, C, O, T, L> WalletSyncer<S, C, TxObfuscationDecryptor<O>, T, L>
where
    S: SecureStorage,
    C: Client,
    O: TransactionObfuscation,
    T: AddressRecovery,
    L: LightClientHandle,
{
    /// Construct with obfuscation config
    pub fn with_obfuscation_config(
        config: ObfuscationSyncerConfig<S, C, O, L>,
        name: String,
        enckey: SecKey,
        wallet_client: T,
    ) -> Result<WalletSyncer<S, C, TxObfuscationDecryptor<O>, T, L>>
    where
        O: TransactionObfuscation,
    {
        let private_key = load_view_key(&config.storage, &name, &enckey)?;
        let decryptor = TxObfuscationDecryptor::new(config.obfuscation, private_key);
        Ok(Self::with_config(
            SyncerConfig {
                storage: config.storage,
                client: config.client,
                options: config.options,
                light_client: config.light_client,
            },
            decryptor,
            name,
            enckey,
            wallet_client,
        ))
    }
}

/// Sync wallet state from blocks.
struct WalletSyncerImpl<
    'a,
    S: SecureStorage,
    C: Client,
    D: TxDecryptor,
    F: FnMut(ProgressReport) -> bool,
    T: AddressRecovery,
    L: LightClientHandle,
> {
    env: &'a mut WalletSyncer<S, C, D, T, L>,
    progress_callback: F,

    // cached state
    wallet: Wallet,
    sync_state: SyncState,
    wallet_state: WalletState,
}

impl<
        'a,
        S: SecureStorage,
        C: Client,
        D: TxDecryptor,
        F: FnMut(ProgressReport) -> bool,
        T: AddressRecovery,
        L: LightClientHandle,
    > WalletSyncerImpl<'a, S, C, D, F, T, L>
{
    fn new(env: &'a mut WalletSyncer<S, C, D, T, L>, progress_callback: F) -> Result<Self> {
        let wallet = service::load_wallet(&env.storage, &env.name, &env.enckey)?
            .err_kind(ErrorKind::InvalidInput, || {
                format!("wallet not found: {}", env.name)
            })?;

        let mstate = service::load_sync_state(&env.storage, &env.name)?;
        let sync_state = if let Some(sync_state) = mstate {
            sync_state
        } else {
            // if fast-forward, don't check genesis fingerprint
            let enable_genesis_fingerprint_check = !env.options.enable_fast_forward;
            get_genesis_sync_state(&env.client, enable_genesis_fingerprint_check)?
        };

        let wallet_state =
            service::load_wallet_state(&env.storage, &env.name, &env.enckey)?.unwrap_or_default();

        Ok(Self {
            env,
            progress_callback,
            wallet,
            sync_state,
            wallet_state,
        })
    }

    fn init_progress(&mut self, height: u64) -> bool {
        (self.progress_callback)(ProgressReport::Init {
            wallet_name: self.env.name.clone(),
            start_block_height: self.sync_state.last_block_height,
            finish_block_height: height,
        })
    }

    fn update_progress(&mut self, height: u64) -> bool {
        (self.progress_callback)(ProgressReport::Update {
            wallet_name: self.env.name.clone(),
            current_block_height: height,
        })
    }

    fn update_state(&mut self, memento: &WalletStateMemento) -> Result<()> {
        self.wallet_state = service::modify_wallet_state(
            &self.env.storage,
            &self.env.name,
            &self.env.enckey,
            |state| state.apply_memento(memento),
        )?;
        Ok(())
    }

    fn save(&mut self, memento: &WalletStateMemento) -> Result<()> {
        service::save_sync_state(&self.env.storage, &self.env.name, &self.sync_state)?;
        self.update_state(memento)?;
        Ok(())
    }

    pub fn handle_recover_addresses_for_transaction(
        &mut self,
        transaction: &Transaction,
    ) -> Result<bool> {
        let mut refetch = false;

        let outputs = transaction.outputs().to_vec();

        for (_i, output) in outputs.iter().enumerate() {
            let newaddress: &ExtendedAddr = &output.address;
            let tmp_refetch = self.env.recover_address.recover_addresses(
                newaddress,
                &self.env.name,
                &self.env.enckey,
                &mut self.wallet,
            )?;

            if tmp_refetch {
                refetch = true;
            }
        }

        Ok(refetch)
    }

    fn handle_recover_addresses(&mut self, blocks: &[FilteredBlock]) -> Result<()> {
        let enclave_txids = blocks
            .iter()
            .flat_map(|block| block.enclave_transaction_ids.iter().copied())
            .collect::<Vec<_>>();
        let enclave_txs = self.env.decryptor.decrypt_tx(&enclave_txids)?;
        let enclave_transactions = enclave_txs
            .iter()
            .map(|tx| (tx.id(), tx))
            .collect::<HashMap<_, _>>();

        for block in blocks {
            for txid in block.enclave_transaction_ids.iter() {
                if let (Some(tx), Some(_fee)) = (
                    enclave_transactions.get(txid),
                    block.valid_transaction_fees.get(txid),
                ) {
                    self.handle_recover_addresses_for_transaction(&tx)?;
                }
            }
        }

        Ok(())
    }

    fn handle_batch(&mut self, blocks: NonEmpty<FilteredBlock>) -> Result<()> {
        let enclave_txids = blocks
            .iter()
            .flat_map(|block| block.enclave_transaction_ids.iter().copied())
            .collect::<Vec<_>>();
        let enclave_txs = self.env.decryptor.decrypt_tx(&enclave_txids)?;

        if self.env.options.enable_address_recovery
            && crate::types::WalletKind::HD == self.wallet.wallet_kind
        {
            // only hdwallet
            self.handle_recover_addresses(&blocks)?;
        }

        let memento = handle_blocks(&self.wallet, &mut self.wallet_state, &blocks, &enclave_txs)
            .map_err(|err| Error::new(ErrorKind::InvalidInput, err.to_string()))?;

        let block = blocks.last();
        self.sync_state.last_block_height = block.block_height;
        self.sync_state.last_app_hash = block.app_hash.clone();
        self.sync_state.last_block_hash = block.block_hash.clone();
        self.sync_state.staking_root = block.staking_root;
        self.save(&memento)?;

        if !self.update_progress(block.block_height) {
            return Err(Error::new(ErrorKind::InvalidInput, "Cancelled by user"));
        }

        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        let status = self.env.client.status()?;
        if status.sync_info.catching_up {
            return Err(Error::new(
                ErrorKind::TendermintRpcError,
                "Tendermint node is catching up with full node (retry after some time)",
            ));
        }

        let (target_height, target_app_hash, target_block_hash) =
            if self.env.options.enable_fast_forward {
                (
                    status.sync_info.latest_block_height.value(),
                    status
                        .sync_info
                        .latest_app_hash
                        .map(|hash| hash.to_string())
                        .unwrap_or_default(),
                    status
                        .sync_info
                        .latest_block_hash
                        .map(|hash| hash.to_string())
                        .unwrap_or_default(),
                )
            } else {
                let light_block = self
                    .env
                    .light_client
                    .verify_to_highest()
                    .err_kind(ErrorKind::VerifyError, || "")?;

                let target_height = light_block.signed_header.header.height.value();
                let target_app_hash = hex::encode_upper(&light_block.signed_header.header.app_hash);
                let target_block_hash = ProdHasher {}
                    .hash_header(&light_block.signed_header.header)
                    .to_string();
                {
                    // wait for the target block results to become available
                    let mut success = false;
                    for _ in 0..10 {
                        if self.env.client.block_results(target_height).is_ok() {
                            success = true;
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    if !success {
                        return Err(Error::new(
                            ErrorKind::TendermintRpcError,
                            "block result for highest light block is not available",
                        ));
                    }
                }
                (target_height, target_app_hash, target_block_hash)
            };

        if !self.init_progress(target_height) {
            return Err(Error::new(ErrorKind::InvalidInput, "Cancelled by user"));
        }

        self.sync_to(target_height, &target_app_hash, &target_block_hash)?;

        Ok(())
    }

    fn sync_to(
        &mut self,
        target_height: u64,
        target_app_hash: &str,
        target_block_hash: &str,
    ) -> Result<()> {
        self.sync_state.trusted = false;

        // Send batch RPC requests to tendermint in chunks of `batch_size` requests per batch call
        for chunk in ((self.sync_state.last_block_height + 1)..=target_height)
            .chunks(self.env.options.batch_size)
            .into_iter()
        {
            let mut batch = Vec::with_capacity(self.env.options.batch_size);
            if self.env.options.enable_fast_forward {
                if let Some(block) = self.fast_forward_status(&target_app_hash, target_height)? {
                    // Fast forward to latest state if possible
                    self.handle_batch((batch, block).into())?;
                    return Ok(());
                }
            }

            let range = chunk.collect::<Vec<u64>>();

            if self.env.options.enable_fast_forward {
                // Get the last block to check if there are any changes
                let block = self.env.client.block(range[range.len() - 1])?;
                if let Some(block) = self.fast_forward_block(&block)? {
                    // Fast forward batch if possible
                    self.handle_batch((batch, block).into())?;
                    continue;
                }
            }

            // Fetch batch details if it cannot be fast forwarded
            let blocks = self.env.client.block_batch(range.iter())?;
            let block_results = self.env.client.block_results_batch(range.iter())?;
            let states = self.env.client.query_state_batch(range.iter().cloned())?;

            for (block, block_result, state) in izip!(
                blocks.into_iter(),
                block_results.into_iter(),
                states.into_iter()
            ) {
                let block = FilteredBlock::from_block(
                    &self.wallet,
                    &self.wallet_state,
                    &block,
                    &block_result,
                    &state,
                )?;

                // verify app hash chain
                if !self.sync_state.last_app_hash.is_empty()
                    && self.sync_state.last_app_hash != block.last_app_hash
                {
                    return Err(Error::new(
                        ErrorKind::VerifyError,
                        "last app hash don't match",
                    ));
                }
                self.sync_state.last_app_hash = block.app_hash.clone();

                // verify block hash chain
                if !self.sync_state.last_block_hash.is_empty()
                    && self.sync_state.last_block_hash != block.last_block_hash
                {
                    return Err(Error::new(
                        ErrorKind::VerifyError,
                        "last block hash don't match",
                    ));
                }
                self.sync_state.last_block_hash = block.block_hash.clone();

                self.update_progress(block.block_height);
                batch.push(block);
            }
            if let Some(non_empty_batch) = NonEmpty::new(batch) {
                self.handle_batch(non_empty_batch)?;
            }
        }

        match self.sync_state.last_block_height.cmp(&target_height) {
            Ordering::Equal => {
                // rollback the pending transaction
                self.rollback_pending_tx(target_height)?;

                if self.sync_state.last_block_hash != target_block_hash {
                    return Err(Error::new(
                        ErrorKind::VerifyError,
                        "target block hash dont match",
                    ));
                };
                self.sync_state.trusted = true;
                service::save_sync_state(&self.env.storage, &self.env.name, &self.sync_state)
            }
            Ordering::Greater => {
                // impossible
                Err(Error::new(
                    ErrorKind::VerifyError,
                    "sync block higher than target",
                ))
            }
            Ordering::Less => {
                // not up-to-date, try again
                log::warn!("not up to date, sync again");
                self.sync_to(target_height, target_app_hash, target_block_hash)
            }
        }
    }

    fn rollback_pending_tx(&mut self, current_block_height: u64) -> Result<()> {
        let mut memento = WalletStateMemento::default();
        let state =
            service::load_wallet_state(&self.env.storage, &self.env.name, &self.env.enckey)?
                .chain(|| (ErrorKind::StorageError, "get wallet state failed"))?;
        for tx_id in state
            .get_rollback_pending_tx(current_block_height, self.env.options.block_height_ensure)
        {
            memento.remove_pending_transaction(tx_id);
        }
        self.save(&memento)
    }

    /// Fast forwards state to given status if app hashes match
    fn fast_forward_status(
        &self,
        current_app_hash: &str,
        current_block_height: u64,
    ) -> Result<Option<FilteredBlock>> {
        if current_app_hash == self.sync_state.last_app_hash {
            let block = self.env.client.block(current_block_height)?;
            let block_result = self.env.client.block_results(current_block_height)?;
            let states = self
                .env
                .client
                .query_state_batch(iter::once(current_block_height))?;
            Ok(Some(FilteredBlock::from_block(
                &self.wallet,
                &self.wallet_state,
                &block,
                &block_result,
                &states[0],
            )?))
        } else {
            Ok(None)
        }
    }

    /// Fast forwards state to given block if app hashes match
    fn fast_forward_block(&mut self, block: &Block) -> Result<Option<FilteredBlock>> {
        let current_app_hash = hex::encode(&block.header.app_hash);

        if current_app_hash == self.sync_state.last_app_hash {
            let current_block_height = block.header.height.value();
            let block_result = self.env.client.block_results(current_block_height)?;
            let states = self
                .env
                .client
                .query_state_batch(iter::once(current_block_height))?;
            Ok(Some(FilteredBlock::from_block(
                &self.wallet,
                &self.wallet_state,
                &block,
                &block_result,
                &states[0],
            )?))
        } else {
            Ok(None)
        }
    }
}

/// testnet v0.5
const CRYPTO_GENESIS_FINGERPRINT: &str =
    "DC05002AAEAB58DA40701073A76A018C9AB02C87BD89ADCB6EE7FE5B419526C8";

/// compute the hash of genesis
pub fn compute_genesis_fingerprint(genesis: &Genesis) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(genesis.app_hash.as_ref());
    for validator in genesis
        .validators
        .iter()
        .sorted_by(|&a, &b| Ord::cmp(&hex::encode(a.address), &hex::encode(&b.address)))
    {
        let hash = validator.hash_bytes();
        let hash: H256 = blake3::hash(&hash).into();
        hasher.update(&hash);
    }
    let genesis_time = genesis.genesis_time.to_string();
    let hash_time: H256 = blake3::hash(genesis_time.as_bytes()).into();
    hasher.update(&hash_time);
    let consensus_params = serde_json::to_string(&genesis.consensus_params)
        .chain(|| (ErrorKind::VerifyError, "Invalid genesis from tendermint"))?;
    let hash_consensus: H256 = blake3::hash(consensus_params.as_bytes()).into();
    hasher.update(&hash_consensus);
    let hash_chain_id: H256 = blake3::hash(genesis.chain_id.as_bytes()).into();
    hasher.update(&hash_chain_id);
    let result = hex::encode(hasher.finalize().as_bytes()).to_uppercase();
    Ok(result)
}

fn check_genesis_fingerprint(genesis: &Genesis) -> Result<()> {
    let hash_setted = std::env::var("CRYPTO_GENESIS_FINGERPRINT")
        .unwrap_or_else(|_| CRYPTO_GENESIS_FINGERPRINT.into());
    let hash_online = compute_genesis_fingerprint(genesis)?;
    if hash_setted == hash_online {
        Ok(())
    } else {
        let msg = format!(
            "genesis-fingerprint from tendermint {} does not match preset genesis-fingerprint {}",
            hash_online, hash_setted
        );
        Err(Error::new(ErrorKind::VerifyError, msg))
    }
}

pub fn get_genesis_sync_state<C: Client>(
    client: &C,
    enable_genesis_fingerprint_check: bool,
) -> Result<SyncState> {
    let genesis = client.genesis()?;

    if enable_genesis_fingerprint_check {
        check_genesis_fingerprint(&genesis)?;
    }
    let accounts = genesis.app_state.unwrap().get_account(
        genesis
            .genesis_time
            .duration_since(Time::unix_epoch())
            .expect("invalid genesis time")
            .as_secs(),
    );
    Ok(SyncState::genesis(compute_staking_root(&accounts)))
}

/// A struct for providing progress report for synchronization
#[derive(Debug, Clone)]
pub enum ProgressReport {
    /// Initial report to send start/finish heights
    Init {
        /// Name of wallet
        wallet_name: String,
        /// Block height from which synchronization started
        start_block_height: u64,
        /// Block height at which synchronization will finish
        finish_block_height: u64,
    },
    /// Report to update progress status
    Update {
        /// Name of wallet
        wallet_name: String,
        /// Current synchronized block height
        current_block_height: u64,
    },
}

/// Structure for representing a block header on Crypto.com Chain,
/// already filtered for current wallet.
#[derive(Debug)]
pub(crate) struct FilteredBlock {
    /// The result app hash of last block
    pub last_app_hash: String,
    /// The result app hash of this block
    pub app_hash: String,
    /// Block height
    pub block_height: u64,
    /// Hash of last block
    pub last_block_hash: String,
    /// Block hash
    pub block_hash: String,
    /// Block time
    pub block_time: Time,
    /// List of successfully committed transaction ids in this block and their fees
    pub valid_transaction_fees: IndexMap<TxId, Fee>,
    /// Bloom filter for view keys and staking addresses
    pub block_filter: BlockFilter,
    /// List of successfully committed transaction of transactions that may need to be queried against
    pub enclave_transaction_ids: Vec<TxId>,
    /// List of un-encrypted transactions (only contains transactions of type `DepositStake` and `UnbondStake`)
    pub staking_transactions: Vec<Transaction>,
    /// staking root after this block
    pub staking_root: H256,
}

impl FilteredBlock {
    /// Decode and filter block data for wallet
    fn from_block(
        wallet: &Wallet,
        wallet_state: &WalletState,
        block: &Block,
        block_result: &BlockResultsResponse,
        state: &ChainState,
    ) -> Result<FilteredBlock> {
        let last_app_hash = hex::encode_upper(&block.header.app_hash);
        let app_hash = hex::encode_upper(
            &state.compute_app_hash(
                block_result
                    .fees()
                    .chain(|| (ErrorKind::VerifyError, "verify block results"))?
                    .keys()
                    .cloned()
                    .collect(),
            ),
        );
        let block_height = block.header.height.value();
        let block_time = block.header.time;
        let last_block_hash = block
            .header
            .last_block_id
            .as_ref()
            .map(|block_id| block_id.hash.to_string())
            .unwrap_or_default();
        let block_hash = ProdHasher {}.hash_header(&block.header).to_string();

        let block_filter = block_result.block_filter()?;

        // first get the incomming staking transactions
        let mut staking_transactions = filter_incomming_staking_transactions(
            &block_result,
            wallet.staking_addresses().iter(),
            block,
        )?;

        // if it is not the incomming staking transaction, maybe it is the outgoing staking transaction
        if staking_transactions.is_empty() {
            staking_transactions = filter_staking_transactions(&block_result, block, wallet_state)?;
        }

        let valid_transaction_fees = block_result.fees()?;

        let enclave_transaction_ids =
            if block_filter.check_view_key(&wallet.view_key.clone().into()) {
                block.enclave_transaction_ids()?
            } else {
                vec![]
            };

        Ok(FilteredBlock {
            last_app_hash,
            app_hash,
            block_height,
            block_time,
            block_hash,
            last_block_hash,
            valid_transaction_fees,
            enclave_transaction_ids,
            block_filter,
            staking_transactions,
            staking_root: state.account_root,
        })
    }
}

/// find the self outgoing staking transactions in the block
fn filter_staking_transactions(
    block_results: &BlockResultsResponse,
    block: &Block,
    wallet_state: &WalletState,
) -> Result<Vec<Transaction>> {
    let outgoing_tx = move |tx: &Transaction| {
        let inputs = tx.inputs();
        for input in inputs {
            if wallet_state.unspent_transactions.get(input).is_some() {
                return true;
            }
            for tx_pending in wallet_state.pending_transactions.values() {
                if tx_pending.used_inputs.contains(input) {
                    return true;
                }
            }
        }
        false
    };
    if block_results.contains_staking() {
        let txs = block
            .staking_transactions()?
            .iter()
            .filter(|&t| outgoing_tx(t))
            .cloned()
            .collect();
        Ok(txs)
    } else {
        Ok(Default::default())
    }
}

/// the staking address in the transaction is self_wallet staking address
fn filter_incomming_staking_transactions<'a>(
    block_results: &BlockResultsResponse,
    staking_addresses: impl Iterator<Item = &'a StakedStateAddress>,
    block: &Block,
) -> Result<Vec<Transaction>> {
    for staking_address in staking_addresses {
        if block_results.contains_account(&staking_address)? {
            return block.staking_transactions();
        }
    }

    Ok(Default::default())
}

fn make_light_client_instance(
    peer_id: PeerId,
    addr: tendermint::net::Address,
    db_path: impl AsRef<Path>,
    trusting_period: Duration,
) -> Result<Instance> {
    let mut peer_map = HashMap::new();
    peer_map.insert(peer_id, addr);

    let timeout = Duration::from_secs(10);
    let io = ProdIo::new(peer_map, Some(timeout));

    let db = sled::open(&db_path).err_kind(ErrorKind::InitializationError, || {
        format!(
            "Unable to initialize sled storage for light client peer at path: {}",
            db_path.as_ref().display()
        )
    })?;

    let mut light_store = SledStore::new(db);

    if light_store.latest(Status::Verified).is_none() {
        // FIXME trust height 1 automatically
        let trusted_state = io
            .fetch_light_block(peer_id, AtHeight::At(1))
            .err_kind(ErrorKind::InitializationError, || {
                "could not retrieve trusted header of block 1"
            })?;
        light_store.insert(trusted_state, Status::Verified);
    }
    let state = State {
        light_store: Box::new(light_store),
        verification_trace: HashMap::new(),
    };

    let options = light_client::Options {
        trust_threshold: TrustThreshold {
            numerator: 1,
            denominator: 3,
        },
        // https://docs.tendermint.com/master/spec/consensus/light-client/verification.html#high-level-solution
        // set a minimal duration because integration test's unbonding period is too short for
        // trusting period.
        trusting_period: max(trusting_period, Duration::from_secs(600)),
        // allowed clock drift between local clocks and BFT time
        // https://docs.tendermint.com/master/spec/consensus/light-client/verification.html#failure-model
        clock_drift: Duration::from_secs(1),
    };

    let verifier = ProdVerifier::default();
    let clock = SystemClock;
    let scheduler = scheduler::basic_bisecting_schedule;

    let light_client = LightClient::new(peer_id, options, clock, scheduler, verifier, io);

    Ok(Instance::new(light_client, state))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Mnemonic;

    use std::fs;
    use std::path::PathBuf;

    use secstr::SecUtf8;

    use chain_core::state::ChainState;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;
    use client_common::tendermint::Client;
    use test_common::block_generator::{BlockGenerator, GeneratorClient};

    use crate::service::save_sync_state;
    use crate::types::WalletKind;
    use crate::wallet::{DefaultWalletClient, WalletClient};
    use chain_core::init::coin::Coin;
    use chain_core::tx::data::{address::ExtendedAddr, output::TxOut};
    use chain_core::tx::data::{Tx, TxId};
    use client_common::PublicKey;
    use std::str::FromStr;

    fn check_wallet_syncer_impl(enable_fast_forward: bool) {
        let storage = MemoryStorage::default();

        let name = "name";
        let passphrase = SecUtf8::from("passphrase");

        let wallet = DefaultWalletClient::new_read_only(storage.clone());

        let (enckey, _) = wallet
            .new_wallet(name, &passphrase, WalletKind::Basic, None)
            .unwrap();

        let client = GeneratorClient::new(BlockGenerator::one_node());
        {
            let mut gen = client.gen.write().unwrap();
            for _ in 0..10 {
                gen.gen_block(&[]);
            }
        }
        let light_client = client.clone();

        let mut syncer = WalletSyncer::with_config(
            SyncerConfig {
                storage,
                client,
                light_client,
                options: SyncerOptions {
                    enable_fast_forward,
                    enable_address_recovery: false,
                    batch_size: 20,
                    block_height_ensure: 50,
                },
            },
            |_txids: &[TxId]| -> Result<Vec<Transaction>> { Ok(vec![]) },
            name.to_owned(),
            enckey,
            wallet,
        );
        let genesis = syncer.client.genesis().unwrap();
        let hash = compute_genesis_fingerprint(&genesis).unwrap();
        std::env::set_var("CRYPTO_GENESIS_FINGERPRINT", hash);
        syncer.sync(|_| true).expect("Unable to synchronize");
    }

    #[test]
    fn check_wallet_syncer() {
        check_wallet_syncer_impl(false);
        check_wallet_syncer_impl(true);
    }

    #[test]
    #[ignore]
    fn check_wallet_syncer_app_hash_on_multiple_tx() {
        #[derive(Clone)]
        struct MockTendermintClient {}
        impl Client for MockTendermintClient {
            fn genesis(&self) -> Result<Genesis> {
                unreachable!()
            }
            fn status(&self) -> Result<StatusResponse> {
                Ok(
                    serde_json::from_str(&read_asset_file("tendermint_status.json"))
                        .expect("tendermint status"),
                )
            }
            fn block(&self, _height: u64) -> Result<Block> {
                Ok(
                    serde_json::from_str(&read_asset_file("tendermint_block.json"))
                        .expect("tendermint block"),
                )
            }
            fn block_batch<'a, T: Iterator<Item = &'a u64>>(
                &self,
                _heights: T,
            ) -> Result<Vec<Block>> {
                unreachable!()
            }
            fn block_results(&self, _height: u64) -> Result<BlockResultsResponse> {
                unreachable!()
            }
            fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
                &self,
                _heights: T,
            ) -> Result<Vec<BlockResultsResponse>> {
                return Ok(serde_json::from_str(&read_asset_file(
                    "tendermint_block_results_batch.json",
                ))
                .expect("tendermint block results batch"));
            }
            fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<BroadcastTxResponse> {
                unreachable!()
            }
            fn query(
                &self,
                _path: &str,
                _data: &[u8],
                _height: Option<Height>,
                _prove: bool,
            ) -> Result<AbciQuery> {
                unreachable!()
            }

            /// Match batch state `abci_query` call to tendermint
            fn query_state_batch<T: Iterator<Item = u64>>(
                &self,
                _heights: T,
            ) -> Result<Vec<ChainState>> {
                Ok(
                    serde_json::from_str(&read_asset_file("tendermint_query_state_batch.json"))
                        .expect("tendermint query state batch"),
                )
            }
        }
        impl Handle for MockTendermintClient {}

        let storage = MemoryStorage::default();
        let name = "name";
        save_sync_state(
            &storage,
            name,
            &SyncState {
                last_block_height: 1745,
                last_app_hash: "3fe291fd64f1140acfe38988a9f8c5b0cb5da43a0214bbd4000035509ce34205"
                    .to_string(),
                last_block_hash: "3fe291fd64f1140acfe38988a9f8c5b0cb5da43a0214bbd4000035509ce34205"
                    .to_string(),
                staking_root: [0u8; 32],
                trusted: true,
            },
        )
        .expect("should save sync state");

        let wallet_passphrase = SecUtf8::from("passphrase");
        let wallet = DefaultWalletClient::new_read_only(storage.clone());

        let (wallet_enckey, _) = wallet
            .new_wallet(name, &wallet_passphrase, WalletKind::Basic, None)
            .expect("create wallet failed");
        let client = MockTendermintClient {};
        let light_client = client.clone();

        let enable_fast_forward = false;

        let mut syncer = WalletSyncer::with_config(
            SyncerConfig {
                storage,
                client,
                light_client,
                options: SyncerOptions {
                    enable_fast_forward,
                    enable_address_recovery: false,
                    batch_size: 20,
                    block_height_ensure: 50,
                },
            },
            |_txids: &[TxId]| -> Result<Vec<Transaction>> { Ok(vec![]) },
            name.to_owned(),
            wallet_enckey,
            wallet,
        );

        syncer.sync(|_| true).expect("sync should succeed");
    }

    fn read_asset_file(filename: &str) -> String {
        let mut path = PathBuf::new();
        path.push(env!("CARGO_MANIFEST_DIR"));
        path.push("src/wallet");
        path.push(format!("syncer_test_assets/{}", filename));

        fs::read_to_string(path).unwrap()
    }

    #[test]

    fn check_handle_recover_addresses_for_transaction_not_owned_address() {
        let storage = MemoryStorage::default();

        let words = Mnemonic::from_secstr(&SecUtf8::from("speed tortoise kiwi forward extend baby acoustic foil coach castle ship purchase unlock base hip erode tag keen present vibrant oyster cotton write fetch")).unwrap();
        let name = "Default1";
        let passphrase = SecUtf8::from("123456");
        let wallet = DefaultWalletClient::new_read_only(storage.clone());
        let enckey = wallet
            .restore_wallet(name, &passphrase, &words)
            .expect("restore wallet 1 failed");

        let client = GeneratorClient::new(BlockGenerator::one_node());
        {
            let mut gen = client.gen.write().unwrap();
            for _ in 0..10 {
                gen.gen_block(&[]);
            }
        }
        let light_client = client.clone();

        let mut syncer = WalletSyncer::with_config(
            SyncerConfig {
                storage,
                client,
                light_client,
                options: SyncerOptions {
                    enable_fast_forward: false,
                    enable_address_recovery: true,
                    batch_size: 20,
                    block_height_ensure: 50,
                },
            },
            |_txids: &[TxId]| -> Result<Vec<Transaction>> { Ok(vec![]) },
            name.to_owned(),
            enckey,
            wallet,
        );
        let genesis = syncer.client.genesis().unwrap();
        let hash = compute_genesis_fingerprint(&genesis).unwrap();
        std::env::set_var("CRYPTO_GENESIS_FINGERPRINT", hash);
        let mut syncimpl = WalletSyncerImpl::new(&mut syncer, |_| true).unwrap();
        let mut tx_core = Tx::new();
        let output = TxOut {
            address: ExtendedAddr::OrTree([0; 32]),
            value: Coin::new(10).unwrap(),
            valid_from: None,
        };
        tx_core.outputs.push(output);
        let tx = Transaction::TransferTransaction(tx_core);

        assert_eq!(
            false,
            syncimpl
                .handle_recover_addresses_for_transaction(&tx)
                .unwrap()
        );
    }

    #[test]
    fn check_handle_recover_addresses_for_transaction_owned_address() {
        let storage = MemoryStorage::default();

        let words = Mnemonic::from_secstr(&SecUtf8::from("speed tortoise kiwi forward extend baby acoustic foil coach castle ship purchase unlock base hip erode tag keen present vibrant oyster cotton write fetch")).unwrap();
        let name = "Default1";
        let passphrase = SecUtf8::from("123456");
        let wallet = DefaultWalletClient::new_read_only(storage.clone());
        let enckey = wallet
            .restore_wallet(name, &passphrase, &words)
            .expect("restore wallet 1 failed");

        let client = GeneratorClient::new(BlockGenerator::one_node());
        {
            let mut gen = client.gen.write().unwrap();
            for _ in 0..10 {
                gen.gen_block(&[]);
            }
        }
        let light_client = client.clone();

        let mut syncer = WalletSyncer::with_config(
            SyncerConfig {
                storage,
                client,
                light_client,
                options: SyncerOptions {
                    enable_fast_forward: false,
                    enable_address_recovery: true,
                    batch_size: 20,
                    block_height_ensure: 50,
                },
            },
            |_txids: &[TxId]| -> Result<Vec<Transaction>> { Ok(vec![]) },
            name.to_owned(),
            enckey.clone(),
            wallet,
        );
        let genesis = syncer.client.genesis().unwrap();
        let hash = compute_genesis_fingerprint(&genesis).unwrap();
        std::env::set_var("CRYPTO_GENESIS_FINGERPRINT", hash);
        let mut syncimpl = WalletSyncerImpl::new(&mut syncer, |_| true).unwrap();

        let mut tx_core = Tx::new();
        let output = TxOut {
            address: ExtendedAddr::from_str(
                "dcro1lgray2pkuqnkvd3hvhcvfta2ku5q0t3x8s03ehslu5xsauv4clfqv4yl40",
            )
            .unwrap(),

            value: Coin::new(10).unwrap(),
            valid_from: None,
        };
        tx_core.outputs.push(output);
        let tx = Transaction::TransferTransaction(tx_core);

        assert_eq!(
            true,
            syncimpl
                .handle_recover_addresses_for_transaction(&tx)
                .unwrap()
        );

        let dummy_viewkey = PublicKey::from(
            &PrivateKey::new().expect("Derive public key from private key should work"),
        );
        let mut dummy_wallet = Wallet::new(dummy_viewkey, WalletKind::HD);

        // already created
        assert_eq!(
            false,
            syncer
                .recover_address
                .recover_addresses(
                    &ExtendedAddr::from_str(
                        "dcro1lgray2pkuqnkvd3hvhcvfta2ku5q0t3x8s03ehslu5xsauv4clfqv4yl40"
                    )
                    .unwrap(),
                    &name,
                    &enckey,
                    &mut dummy_wallet
                )
                .unwrap()
        );
    }
}

/// [new light client design](https://github.com/informalsystems/tendermint-rs/blob/master/docs/architecture/adr-006-light-client-refactor.md)
pub fn spawn_light_client_supervisor(
    db_path: &Path,
    addr: &str,
    trusting_period: Duration,
) -> Result<LightClientWrapper<impl Handle + 'static>> {
    // convert "ws://host:port/websocket" to "tcp://host:port"
    let addr = format!(
        "tcp://{}",
        strip_prefix(addr, "ws://")
            .and_then(|addr| strip_suffix(addr, "/websocket"))
            .err_kind(ErrorKind::InvalidInput, || "invalid tendermint rpc address")?
    );
    let addr = tendermint::net::Address::from_str(&addr).unwrap();

    // FIXME use actual tendermint node id as peer id
    let primary: PeerId = "BADFADAD0BEFEEDC0C0ADEADBEEFC0FFEEFACADE".parse().unwrap();
    let witness: PeerId = "CEFEEDBADFADAD0C0CEEFACADE0ADEADBEEFC0FF".parse().unwrap();

    let primary_path = db_path.join(primary.to_string());
    let witness_path = db_path.join(witness.to_string());

    let primary_instance =
        make_light_client_instance(primary, addr.clone(), primary_path, trusting_period)?;
    let witness_instance =
        make_light_client_instance(witness, addr.clone(), witness_path, trusting_period)?;

    let mut peer_addr = HashMap::new();
    peer_addr.insert(primary, addr.clone());
    peer_addr.insert(witness, addr);

    let peer_list = PeerList::builder()
        .primary(primary, primary_instance)
        .witness(witness, witness_instance)
        .build();
    let mut supervisor = Supervisor::new(
        peer_list,
        ProdForkDetector::default(),
        ProdEvidenceReporter::new(peer_addr),
    );
    let handle = supervisor.handle();
    std::thread::spawn(|| supervisor.run());
    Ok(LightClientWrapper {
        inner: Arc::new(handle),
    })
}

/// A wrapper over light client `Handle` which supports `Clone`
pub struct LightClientWrapper<L> {
    inner: Arc<L>,
}

impl<L> Clone for LightClientWrapper<L> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<L: Handle> Handle for LightClientWrapper<L> {
    fn latest_trusted(
        &self,
    ) -> result::Result<Option<LightBlock>, tendermint_light_client::errors::Error> {
        self.inner.latest_trusted()
    }

    /// Verify to the highest block.
    fn verify_to_highest(
        &self,
    ) -> result::Result<LightBlock, tendermint_light_client::errors::Error> {
        self.inner.verify_to_highest()
    }

    /// Verify to the block at the given height.
    fn verify_to_target(
        &self,
        height: u64,
    ) -> result::Result<LightBlock, tendermint_light_client::errors::Error> {
        self.inner.verify_to_target(height)
    }

    /// Terminate the underlying [`Supervisor`].
    fn terminate(&self) -> result::Result<(), tendermint_light_client::errors::Error> {
        self.inner.terminate()
    }
}

/// FIXME change to str::strip_prefix after toolchain upgraded.
fn strip_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && &s[0..prefix.len()] == prefix {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// FIXME change to str::strip_suffix after toolchain upgraded.
fn strip_suffix<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    if s.len() >= suffix.len() && &s[s.len() - suffix.len()..s.len()] == suffix {
        Some(&s[0..s.len() - suffix.len()])
    } else {
        None
    }
}
