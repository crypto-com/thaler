#![allow(missing_docs)]
use indexmap::IndexMap;
use itertools::{izip, Itertools};
use non_empty_vec::NonEmpty;
use std::sync::mpsc::Sender;

use chain_core::common::H256;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_tx_filter::BlockFilter;
use client_common::tendermint::types::{Block, BlockExt, BlockResults, Status, Time};
use client_common::tendermint::Client;
use client_common::{
    Error, ErrorKind, PrivateKey, Result, ResultExt, SecKey, SecureStorage, Transaction,
};

use super::syncer_logic::handle_blocks;
use crate::service;
use crate::service::{KeyService, SyncState, Wallet, WalletState, WalletStateMemento};
use crate::TransactionObfuscation;

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

/// Common configs for wallet syncer with `TransactionObfuscation`
#[derive(Clone)]
pub struct ObfuscationSyncerConfig<S: SecureStorage, C: Client, O: TransactionObfuscation> {
    // services
    pub storage: S,
    pub client: C,
    pub obfuscation: O,

    // configs
    pub enable_fast_forward: bool,
    pub batch_size: usize,
    pub block_height_ensure: u64,
}

impl<S: SecureStorage, C: Client, O: TransactionObfuscation> ObfuscationSyncerConfig<S, C, O> {
    /// Construct ObfuscationSyncerConfig
    pub fn new(
        storage: S,
        client: C,
        obfuscation: O,
        enable_fast_forward: bool,
        batch_size: usize,
        block_height_ensure: u64,
    ) -> ObfuscationSyncerConfig<S, C, O> {
        ObfuscationSyncerConfig {
            storage,
            client,
            obfuscation,
            enable_fast_forward,
            batch_size,
            block_height_ensure,
        }
    }
}

/// Common configs for wallet syncer
#[derive(Clone)]
pub struct SyncerConfig<S: SecureStorage, C: Client> {
    // services
    storage: S,
    client: C,

    // configs
    enable_fast_forward: bool,
    batch_size: usize,
    block_height_ensure: u64,
}

/// Wallet Syncer
#[derive(Clone)]
pub struct WalletSyncer<S: SecureStorage, C: Client, D: TxDecryptor> {
    // common
    storage: S,
    client: C,
    progress_reporter: Option<Sender<ProgressReport>>,
    enable_fast_forward: bool,
    batch_size: usize,
    block_height_ensure: u64,

    // wallet
    decryptor: D,
    name: String,
    enckey: SecKey,
}

impl<S, C, D> WalletSyncer<S, C, D>
where
    S: SecureStorage,
    C: Client,
    D: TxDecryptor,
{
    /// Construct with common config
    pub fn with_config(
        config: SyncerConfig<S, C>,
        decryptor: D,
        progress_reporter: Option<Sender<ProgressReport>>,
        name: String,
        enckey: SecKey,
    ) -> WalletSyncer<S, C, D> {
        Self {
            storage: config.storage,
            client: config.client,
            decryptor,
            progress_reporter,
            name,
            enckey,
            enable_fast_forward: config.enable_fast_forward,
            batch_size: config.batch_size,
            block_height_ensure: config.block_height_ensure,
        }
    }

    /// Delete sync state and wallet state.
    pub fn reset_state(&self) -> Result<()> {
        service::delete_sync_state(&self.storage, &self.name)?;
        service::delete_wallet_state(&self.storage, &self.name)?;
        Ok(())
    }

    /// Load wallet state in memory, sync it to most recent latest, then drop the memory cache.
    pub fn sync(&self) -> Result<()> {
        WalletSyncerImpl::new(self)?.sync()
    }
}

fn load_view_key<S: SecureStorage>(storage: &S, name: &str, enckey: &SecKey) -> Result<PrivateKey> {
    KeyService::new(storage.clone())
        .wallet_private_key(name, enckey)?
        .err_kind(ErrorKind::InvalidInput, || {
            format!("wallet private view key not found: {}", name)
        })
}

impl<S, C, O> WalletSyncer<S, C, TxObfuscationDecryptor<O>>
where
    S: SecureStorage,
    C: Client,
    O: TransactionObfuscation,
{
    /// Construct with obfuscation config
    pub fn with_obfuscation_config(
        config: ObfuscationSyncerConfig<S, C, O>,
        progress_reporter: Option<Sender<ProgressReport>>,
        name: String,
        enckey: SecKey,
    ) -> Result<WalletSyncer<S, C, TxObfuscationDecryptor<O>>>
    where
        O: TransactionObfuscation,
    {
        let decryptor = TxObfuscationDecryptor::new(
            config.obfuscation,
            load_view_key(&config.storage, &name, &enckey)?,
        );
        Ok(Self::with_config(
            SyncerConfig {
                storage: config.storage,
                client: config.client,
                enable_fast_forward: config.enable_fast_forward,
                batch_size: config.batch_size,
                block_height_ensure: config.block_height_ensure,
            },
            decryptor,
            progress_reporter,
            name,
            enckey,
        ))
    }
}

/// Sync wallet state from blocks.
struct WalletSyncerImpl<'a, S: SecureStorage, C: Client, D: TxDecryptor> {
    env: &'a WalletSyncer<S, C, D>,

    // cached state
    wallet: Wallet,
    sync_state: SyncState,
    wallet_state: WalletState,
}

impl<'a, S: SecureStorage, C: Client, D: TxDecryptor> WalletSyncerImpl<'a, S, C, D> {
    fn new(env: &'a WalletSyncer<S, C, D>) -> Result<Self> {
        let wallet = service::load_wallet(&env.storage, &env.name, &env.enckey)?
            .err_kind(ErrorKind::InvalidInput, || {
                format!("wallet not found: {}", env.name)
            })?;

        let sync_state = service::load_sync_state(&env.storage, &env.name)?;
        let sync_state = if let Some(sync_state) = sync_state {
            sync_state
        } else {
            SyncState::genesis(env.client.genesis()?.validators)
        };

        let wallet_state =
            service::load_wallet_state(&env.storage, &env.name, &env.enckey)?.unwrap_or_default();

        Ok(Self {
            env,
            wallet,
            sync_state,
            wallet_state,
        })
    }

    fn init_progress(&self, height: u64) {
        if let Some(ref sender) = &self.env.progress_reporter {
            let _ = sender.send(ProgressReport::Init {
                wallet_name: self.env.name.clone(),
                start_block_height: self.sync_state.last_block_height,
                finish_block_height: height,
            });
        }
    }

    fn update_progress(&self, height: u64) {
        if let Some(ref sender) = &self.env.progress_reporter {
            let _ = sender.send(ProgressReport::Update {
                wallet_name: self.env.name.clone(),
                current_block_height: height,
            });
        }
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

    fn handle_batch(&mut self, blocks: NonEmpty<FilteredBlock>) -> Result<()> {
        let enclave_txids = blocks
            .iter()
            .flat_map(|block| block.enclave_transaction_ids.iter().copied())
            .collect::<Vec<_>>();
        let enclave_txs = self.env.decryptor.decrypt_tx(&enclave_txids)?;

        let memento = handle_blocks(&self.wallet, &self.wallet_state, &blocks, &enclave_txs)
            .map_err(|err| Error::new(ErrorKind::InvalidInput, err.to_string()))?;

        let block = blocks.last();
        self.sync_state.last_block_height = block.block_height;
        self.sync_state.last_app_hash = block.app_hash.clone();
        self.update_progress(block.block_height);

        self.save(&memento)
    }

    fn sync(&mut self) -> Result<()> {
        let status = self.env.client.status()?;

        if status.sync_info.catching_up {
            return Err(Error::new(
                ErrorKind::TendermintRpcError,
                "Tendermint node is catching up with full node (retry after some time)",
            ));
        }
        let current_block_height = status.sync_info.latest_block_height.value();
        self.init_progress(current_block_height);

        // Send batch RPC requests to tendermint in chunks of `batch_size` requests per batch call
        for chunk in ((self.sync_state.last_block_height + 1)..=current_block_height)
            .chunks(self.env.batch_size)
            .into_iter()
        {
            let mut batch = Vec::with_capacity(self.env.batch_size);
            if self.env.enable_fast_forward {
                if let Some(block) = self.fast_forward_status(&status)? {
                    // Fast forward to latest state if possible
                    self.handle_batch((batch, block).into())?;
                    return Ok(());
                }
            }

            let range = chunk.collect::<Vec<u64>>();

            // Get the last block to check if there are any changes
            let block = self.env.client.block(range[range.len() - 1])?;
            if self.env.enable_fast_forward {
                if let Some(block) = self.fast_forward_block(&block)? {
                    // Fast forward batch if possible
                    self.handle_batch((batch, block).into())?;
                    continue;
                }
            }

            // Fetch batch details if it cannot be fast forwarded
            let (blocks, trusted_state) = self
                .env
                .client
                .block_batch_verified(self.sync_state.trusted_state.clone(), range.iter())?;
            self.sync_state.trusted_state = trusted_state;
            let block_results = self.env.client.block_results_batch(range.iter())?;
            let states = self.env.client.query_state_batch(range.iter().cloned())?;

            let mut app_hash: Option<H256> = None;
            for (block, block_result, state) in izip!(
                blocks.into_iter(),
                block_results.into_iter(),
                states.into_iter()
            ) {
                if let Some(app_hash) = app_hash {
                    let header_app_hash = block
                        .header
                        .app_hash
                        .err_kind(ErrorKind::VerifyError, || "header don't have app_hash")?;
                    if app_hash != header_app_hash.as_bytes() {
                        return Err(Error::new(
                            ErrorKind::VerifyError,
                            "state app hash don't match block header",
                        ));
                    }
                }
                app_hash = Some(
                    state.compute_app_hash(
                        block_result
                            .fees()
                            .chain(|| (ErrorKind::VerifyError, "verify block results"))?
                            .keys()
                            .cloned()
                            .collect(),
                    ),
                );
                if self.env.enable_fast_forward {
                    if let Some(block) = self.fast_forward_status(&status)? {
                        // Fast forward to latest state if possible
                        self.handle_batch((batch, block).into())?;
                        return Ok(());
                    }
                }

                let block = FilteredBlock::from_block(&self.wallet, &block, &block_result)?;
                self.update_progress(block.block_height);
                batch.push(block);
            }
            if let Some(non_empty_batch) = NonEmpty::new(batch) {
                self.handle_batch(non_empty_batch)?;
            }
        }
        // rollback the pending transaction
        self.rollback_pending_tx(current_block_height)
    }

    fn rollback_pending_tx(&mut self, current_block_height: u64) -> Result<()> {
        let mut memento = WalletStateMemento::default();
        let state =
            service::load_wallet_state(&self.env.storage, &self.env.name, &self.env.enckey)?
                .chain(|| (ErrorKind::StorageError, "get wallet state failed"))?;
        for tx_id in
            state.get_rollback_pending_tx(current_block_height, self.env.block_height_ensure)
        {
            memento.remove_pending_transaction(tx_id);
        }
        self.save(&memento)
    }

    /// Fast forwards state to given status if app hashes match
    fn fast_forward_status(&self, status: &Status) -> Result<Option<FilteredBlock>> {
        let current_app_hash = status
            .sync_info
            .latest_app_hash
            .ok_or_else(|| Error::new(ErrorKind::TendermintRpcError, "latest_app_hash not found"))?
            .to_string();

        if current_app_hash == self.sync_state.last_app_hash {
            let current_block_height = status.sync_info.latest_block_height.value();

            let block = self.env.client.block(current_block_height)?;
            let block_result = self.env.client.block_results(current_block_height)?;

            Ok(Some(FilteredBlock::from_block(
                &self.wallet,
                &block,
                &block_result,
            )?))
        } else {
            Ok(None)
        }
    }

    /// Fast forwards state to given block if app hashes match
    fn fast_forward_block(&mut self, block: &Block) -> Result<Option<FilteredBlock>> {
        let current_app_hash = block
            .header
            .app_hash
            .err_kind(ErrorKind::TendermintRpcError, || "app_hash not found")?
            .to_string();

        if current_app_hash == self.sync_state.last_app_hash {
            let current_block_height = block.header.height.value();
            let block_result = self.env.client.block_results(current_block_height)?;
            Ok(Some(FilteredBlock::from_block(
                &self.wallet,
                &block,
                &block_result,
            )?))
        } else {
            Ok(None)
        }
    }
}

/// A struct for providing progress report for synchronization
#[derive(Debug)]
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
    /// App hash of block
    pub app_hash: String,
    /// Block height
    pub block_height: u64,
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
}

impl FilteredBlock {
    /// Decode and filter block data for wallet
    fn from_block(
        wallet: &Wallet,
        block: &Block,
        block_result: &BlockResults,
    ) -> Result<FilteredBlock> {
        let app_hash = block
            .header
            .app_hash
            .ok_or_else(|| Error::new(ErrorKind::TendermintRpcError, "app_hash not found"))?
            .to_string();
        let block_height = block.header.height.value();
        let block_time = block.header.time;

        let block_filter = block_result.block_filter()?;

        let staking_transactions =
            filter_staking_transactions(&block_result, wallet.staking_addresses().iter(), block)?;

        let valid_transaction_fees = block_result.fees()?;

        let enclave_transaction_ids =
            if block_filter.check_view_key(&wallet.view_key.clone().into()) {
                block.enclave_transaction_ids()?
            } else {
                vec![]
            };

        Ok(FilteredBlock {
            app_hash,
            block_height,
            block_time,
            valid_transaction_fees,
            enclave_transaction_ids,
            block_filter,
            staking_transactions,
        })
    }
}

fn filter_staking_transactions<'a>(
    block_results: &BlockResults,
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;

    use secstr::SecUtf8;

    use chain_core::state::ChainState;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;
    use client_common::tendermint::{lite, Client};
    use test_common::block_generator::{BlockGenerator, GeneratorClient};

    use crate::service::save_sync_state;
    use crate::types::WalletKind;
    use crate::wallet::{DefaultWalletClient, WalletClient};

    fn check_wallet_syncer_impl(enable_fast_forward: bool) {
        let storage = MemoryStorage::default();

        let name = "name";
        let passphrase = SecUtf8::from("passphrase");

        let wallet = DefaultWalletClient::new_read_only(storage.clone());

        let (enckey, _) = wallet
            .new_wallet(name, &passphrase, WalletKind::Basic)
            .unwrap();

        let client = GeneratorClient::new(BlockGenerator::one_node());
        {
            let mut gen = client.gen.write().unwrap();
            for _ in 0..10 {
                gen.gen_block(&[]);
            }
        }

        let syncer = WalletSyncer::with_config(
            SyncerConfig {
                storage,
                client,
                enable_fast_forward,
                batch_size: 20,
                block_height_ensure: 50,
            },
            |_txids: &[TxId]| -> Result<Vec<Transaction>> { Ok(vec![]) },
            None,
            name.to_owned(),
            enckey,
        );
        syncer.sync().expect("Unable to synchronize");
    }

    #[test]
    fn check_wallet_syncer() {
        check_wallet_syncer_impl(false);
        check_wallet_syncer_impl(true);
    }

    #[test]
    fn check_wallet_syncer_app_hash_on_multiple_tx() {
        #[derive(Clone)]
        struct MockTendermintClient {}
        impl Client for MockTendermintClient {
            fn genesis(&self) -> Result<Genesis> {
                unreachable!()
            }
            fn status(&self) -> Result<Status> {
                Ok(serde_json::from_str(&read_asset_file("tendermint_status.json")).unwrap())
            }
            fn block(&self, _height: u64) -> Result<Block> {
                Ok(serde_json::from_str(&read_asset_file("tendermint_block.json")).unwrap())
            }
            fn block_batch<'a, T: Iterator<Item = &'a u64>>(
                &self,
                _heights: T,
            ) -> Result<Vec<Block>> {
                unreachable!()
            }
            fn block_results(&self, _height: u64) -> Result<BlockResults> {
                unreachable!()
            }
            fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
                &self,
                _heights: T,
            ) -> Result<Vec<BlockResults>> {
                return Ok(serde_json::from_str(&read_asset_file(
                    "tendermint_block_results_batch.json",
                ))
                .unwrap());
            }
            fn block_batch_verified<'a, T: Clone + Iterator<Item = &'a u64>>(
                &self,
                _state: lite::TrustedState,
                _heights: T,
            ) -> Result<(Vec<Block>, lite::TrustedState)> {
                let blocks: Vec<Block> = serde_json::from_str(&read_asset_file(
                    "tendermint_block_batch_verified_blocks.json",
                ))
                .unwrap();
                let trusted_state: lite::TrustedState = serde_json::from_str(&read_asset_file(
                    "tendermint_block_batch_verified_trusted_state.json",
                ))
                .unwrap();
                Ok((blocks, trusted_state))
            }
            fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<BroadcastTxResponse> {
                unreachable!()
            }
            fn query(&self, _path: &str, _data: &[u8]) -> Result<AbciQuery> {
                unreachable!()
            }

            /// Match batch state `abci_query` call to tendermint
            fn query_state_batch<T: Iterator<Item = u64>>(
                &self,
                _heights: T,
            ) -> Result<Vec<ChainState>> {
                Ok(
                    serde_json::from_str(&read_asset_file("tendermint_query_state_batch.json"))
                        .unwrap(),
                )
            }
        }

        let storage = MemoryStorage::default();
        let name = "name";
        let trusted_state: lite::TrustedState =
            serde_json::from_str(&read_asset_file("sync_state_trusted_state.json")).unwrap();
        save_sync_state(
            &storage,
            name,
            &SyncState {
                last_block_height: 4820,
                last_app_hash: "8F0702AADD083A2524BCAAD76B7B192BBFE5AE3449777FCB9060CD401A4E7D1F"
                    .to_string(),
                trusted_state,
            },
        )
        .expect("should save sync state");

        let wallet_passphrase = SecUtf8::from("passphrase");
        let wallet = DefaultWalletClient::new_read_only(storage.clone());

        let (wallet_enckey, _) = wallet
            .new_wallet(name, &wallet_passphrase, WalletKind::Basic)
            .unwrap();
        let client = MockTendermintClient {};

        let enable_fast_forward = false;
        let syncer = WalletSyncer::with_config(
            SyncerConfig {
                storage,
                client,
                enable_fast_forward,
                batch_size: 20,
                block_height_ensure: 50,
            },
            |_txids: &[TxId]| -> Result<Vec<Transaction>> { Ok(vec![]) },
            None,
            name.to_owned(),
            wallet_enckey,
        );

        syncer.sync().expect("sync should succeed");
    }

    fn read_asset_file(filename: &str) -> String {
        let mut path = PathBuf::new();
        path.push(env!("CARGO_MANIFEST_DIR"));
        path.push("src/wallet");
        path.push(format!("syncer_test_assets/{}", filename));

        fs::read_to_string(path).unwrap()
    }
}
