use std::collections::BTreeSet;
use std::sync::mpsc::Sender;

use itertools::{izip, Itertools};
use secstr::SecUtf8;
use tendermint::validator;

use chain_core::common::H256;
use chain_core::state::account::StakedStateAddress;
use client_common::tendermint::types::{Block, BlockExt, BlockResults, Status};
use client_common::tendermint::{lite, Client};
use client_common::{BlockHeader, Error, ErrorKind, Result, ResultExt, Storage, Transaction};

use crate::service::{GlobalStateService, WalletService, WalletStateService};
use crate::BlockHandler;

const DEFAULT_BATCH_SIZE: usize = 20;

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

/// Synchronizer for transaction index which can be triggered manually
#[derive(Clone)]
pub struct ManualSynchronizer<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    wallet_service: WalletService<S>,
    wallet_state_service: WalletStateService<S>,
    global_state_service: GlobalStateService<S>,
    client: C,
    block_handler: H,
    enable_fast_forward: bool,
}

impl<S, C, H> ManualSynchronizer<S, C, H>
where
    S: Storage + Clone,
    C: Client,
    H: BlockHandler,
{
    /// Creates a new instance of `ManualSynchronizer`
    #[inline]
    pub fn new(storage: S, client: C, block_handler: H, enable_fast_forward: bool) -> Self {
        Self {
            wallet_service: WalletService::new(storage.clone()),
            wallet_state_service: WalletStateService::new(storage.clone()),
            global_state_service: GlobalStateService::new(storage),
            client,
            block_handler,
            enable_fast_forward,
        }
    }
}

impl<S, C, H> ManualSynchronizer<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    /// Synchronizes transaction index for given view key with Crypto.com Chain (from last known height)
    pub fn sync(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        batch_size: Option<usize>,
        progress_reporter: Option<Sender<ProgressReport>>,
    ) -> Result<()> {
        let trust_state = self.load_trust_state()?;
        let status = self.client.status()?;

        let last_block_height = self
            .global_state_service
            .last_block_height(name, passphrase)?;
        let current_block_height = status.sync_info.latest_block_height.value();

        if let Some(ref sender) = &progress_reporter {
            let _ = sender.send(ProgressReport::Init {
                wallet_name: name.to_owned(),
                start_block_height: last_block_height,
                finish_block_height: current_block_height,
            });
        }

        let staking_addresses = self.wallet_service.staking_addresses(name, passphrase)?;

        // Send batch RPC requests to tendermint in chunks of `batch_size` requests per batch call
        for chunk in ((last_block_height + 1)..=current_block_height)
            .chunks(batch_size.unwrap_or(DEFAULT_BATCH_SIZE))
            .into_iter()
        {
            if self.enable_fast_forward
                && self.fast_forward_status(
                    name,
                    passphrase,
                    &staking_addresses,
                    &status,
                    &progress_reporter,
                )?
            {
                // Fast forward to latest state if possible
                return Ok(());
            }

            let range = chunk.collect::<Vec<u64>>();

            // Get the last block to check if there are any changes
            let block = self.client.block(range[range.len() - 1])?;
            if self.enable_fast_forward
                && self.fast_forward_block(
                    name,
                    passphrase,
                    &staking_addresses,
                    &block,
                    &progress_reporter,
                )?
            {
                // Fast forward batch if possible
                continue;
            }

            // Fetch batch details if it cannot be fast forwarded
            let (blocks, trust_state) = self
                .client
                .block_batch_verified(trust_state.clone(), range.iter())?;
            let block_results = self.client.block_results_batch(range.iter())?;
            let states = self.client.query_state_batch(range.iter().cloned())?;

            let mut app_hash: Option<H256> = None;
            for (block, block_result, state) in izip!(
                blocks.into_iter(),
                block_results.into_iter(),
                states.into_iter()
            ) {
                if let Some(app_hash) = app_hash {
                    let header_app_hash = block.header.app_hash.ok_or_else(|| {
                        Error::new(ErrorKind::VerifyError, "header don't have app_hash")
                    })?;
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
                            .transaction_ids()
                            .chain(|| (ErrorKind::VerifyError, "verify block results"))?,
                    ),
                );
                if self.enable_fast_forward
                    && self.fast_forward_status(
                        name,
                        passphrase,
                        &staking_addresses,
                        &status,
                        &progress_reporter,
                    )?
                {
                    // Fast forward to latest state if possible
                    return Ok(());
                }

                let block_header = prepare_block_header(&staking_addresses, &block, &block_result)?;
                self.block_handler.on_next(name, passphrase, block_header)?;

                if let Some(ref sender) = &progress_reporter {
                    let _ = sender.send(ProgressReport::Update {
                        wallet_name: name.to_owned(),
                        current_block_height: block.header.height.value(),
                    });
                }
            }

            self.global_state_service.save_trust_state(&trust_state)?;
        }

        Ok(())
    }

    /// Synchronizes transaction index for given view key with Crypto.com Chain (from genesis)
    #[inline]
    pub fn sync_all(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        batch_size: Option<usize>,
        progress_reporter: Option<Sender<ProgressReport>>,
    ) -> Result<()> {
        self.global_state_service
            .delete_global_state(name, passphrase)?;
        self.wallet_state_service
            .delete_wallet_state(name, passphrase)?;
        self.sync(name, passphrase, batch_size, progress_reporter)
    }

    /// Fast forwards state to given status if app hashes match
    fn fast_forward_status(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        staking_addresses: &BTreeSet<StakedStateAddress>,
        status: &Status,
        progress_reporter: &Option<Sender<ProgressReport>>,
    ) -> Result<bool> {
        let last_app_hash = self.global_state_service.last_app_hash(name, passphrase)?;
        let current_app_hash = status
            .sync_info
            .latest_app_hash
            .ok_or_else(|| Error::new(ErrorKind::TendermintRpcError, "latest_app_hash not found"))?
            .to_string();

        if current_app_hash == last_app_hash {
            let current_block_height = status.sync_info.latest_block_height.value();

            let block = self.client.block(current_block_height)?;
            let block_result = self.client.block_results(current_block_height)?;

            let block_header = prepare_block_header(staking_addresses, &block, &block_result)?;
            self.block_handler.on_next(name, passphrase, block_header)?;

            if let Some(ref sender) = progress_reporter {
                let _ = sender.send(ProgressReport::Update {
                    wallet_name: name.to_owned(),
                    current_block_height,
                });
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Fast forwards state to given block if app hashes match
    fn fast_forward_block(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        staking_addresses: &BTreeSet<StakedStateAddress>,
        block: &Block,
        progress_reporter: &Option<Sender<ProgressReport>>,
    ) -> Result<bool> {
        let last_app_hash = self.global_state_service.last_app_hash(name, passphrase)?;
        let current_app_hash = block
            .header
            .app_hash
            .ok_or_else(|| Error::new(ErrorKind::TendermintRpcError, "app_hash not found"))?
            .to_string();

        if current_app_hash == last_app_hash {
            let current_block_height = block.header.height.value();

            let block_result = self.client.block_results(current_block_height)?;

            let block_header = prepare_block_header(staking_addresses, &block, &block_result)?;
            self.block_handler.on_next(name, passphrase, block_header)?;

            if let Some(ref sender) = progress_reporter {
                let _ = sender.send(ProgressReport::Update {
                    wallet_name: name.to_owned(),
                    current_block_height,
                });
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn load_trust_state(&self) -> Result<lite::TrustedState> {
        let opt = self.global_state_service.load_trust_state()?;
        match opt {
            None => Ok(lite::TrustedState {
                header: None,
                validators: validator::Set::new(self.client.genesis()?.validators),
            }),
            Some(st) => Ok(st),
        }
    }
}

fn check_unencrypted_transactions(
    block_results: &BlockResults,
    staking_addresses: &BTreeSet<StakedStateAddress>,
    block: &Block,
) -> Result<Vec<Transaction>> {
    for staking_address in staking_addresses {
        if block_results.contains_account(&staking_address)? {
            return block.unencrypted_transactions();
        }
    }

    Ok(Default::default())
}

fn prepare_block_header(
    staking_addresses: &BTreeSet<StakedStateAddress>,
    block: &Block,
    block_result: &BlockResults,
) -> Result<BlockHeader> {
    let app_hash = block
        .header
        .app_hash
        .ok_or_else(|| Error::new(ErrorKind::TendermintRpcError, "app_hash not found"))?
        .to_string();
    let block_height = block.header.height.value();
    let block_time = block.header.time;

    let transaction_ids = block_result.transaction_ids()?;
    let block_filter = block_result.block_filter()?;

    let unencrypted_transactions =
        check_unencrypted_transactions(&block_result, staking_addresses, block)?;

    Ok(BlockHeader {
        app_hash,
        block_height,
        block_time,
        transaction_ids,
        block_filter,
        unencrypted_transactions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use base64::encode;
    use parity_scale_codec::Encode;
    use secp256k1::recovery::{RecoverableSignature, RecoveryId};

    use chain_core::common::{TendermintEventKey, TendermintEventType};
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::state::account::{
        StakedStateAddress, StakedStateOpAttributes, StakedStateOpWitness, UnbondTx,
    };
    use chain_core::state::ChainState;
    use chain_core::tx::TxAux;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::lite;
    use client_common::tendermint::mock;
    use client_common::tendermint::types::*;
    use client_common::ErrorKind;
    use test_common::block_generator::BlockGenerator;

    use crate::types::WalletKind;
    use crate::wallet::{DefaultWalletClient, WalletClient};

    fn unbond_transaction() -> TxAux {
        let addr = StakedStateAddress::from(
            RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap(),
        );
        TxAux::UnbondStakeTx(
            UnbondTx::new(
                addr,
                0,
                Coin::new(100).unwrap(),
                StakedStateOpAttributes::new(0),
            ),
            StakedStateOpWitness::BasicRedeem(
                RecoverableSignature::from_compact(
                    &[
                        0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f, 0x04, 0x77, 0x2b, 0x6f,
                        0x92, 0x1f, 0x0b, 0xa6, 0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
                        0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98, 0x4c, 0x1a, 0x97, 0x16,
                        0x52, 0xe0, 0xad, 0xa8, 0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
                        0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06, 0x8d, 0x12, 0xee, 0xd0,
                        0x09, 0xb6, 0x8c, 0x89,
                    ],
                    RecoveryId::from_i32(1).unwrap(),
                )
                .unwrap(),
            ),
        )
    }

    struct MockBlockHandler;

    impl BlockHandler for MockBlockHandler {
        fn on_next(
            &self,
            _name: &str,
            _passphrase: &SecUtf8,
            _block_header: BlockHeader,
        ) -> Result<()> {
            Ok(())
        }
    }

    struct MockClient {
        staking_address: StakedStateAddress,
    }

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            Ok(mock::genesis())
        }

        fn status(&self) -> Result<Status> {
            Ok(Status {
                sync_info: status::SyncInfo {
                    latest_block_height: Height::default().increment(),
                    latest_app_hash: Some(
                        Hash::from_str(
                            "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C",
                        )
                        .unwrap(),
                    ),
                    ..mock::sync_info()
                },
                ..mock::status_response()
            })
        }

        fn block(&self, height: u64) -> Result<Block> {
            if height == 1 {
                Ok(Block {
                    header: Header {
                        app_hash: Some(
                            Hash::from_str(
                                "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3D",
                            )
                            .unwrap(),
                        ),
                        height: height.into(),
                        time: Time::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                        ..mock::header()
                    },
                    ..mock::block()
                })
            } else if height == 2 {
                Ok(Block {
                    header: Header {
                        app_hash: Some(
                            Hash::from_str(
                                "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C",
                            )
                            .unwrap(),
                        ),
                        height: height.into(),
                        time: Time::from_str("2019-04-10T09:38:41.735577Z").unwrap(),
                        ..mock::header()
                    },
                    data: Data::new(vec![abci::Transaction::new(unbond_transaction().encode())]),
                    ..mock::block()
                })
            } else {
                Err(ErrorKind::InvalidInput.into())
            }
        }

        fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, heights: T) -> Result<Vec<Block>> {
            heights.map(|height| self.block(*height)).collect()
        }

        fn block_results(&self, height: u64) -> Result<BlockResults> {
            if height == 1 {
                Ok(BlockResults {
                    height: Height::default(),
                    results: Results {
                        deliver_tx: None,
                        end_block: Some(EndBlock {
                            events: vec![Event {
                                event_type: TendermintEventType::BlockFilter.to_string(),
                                attributes: vec![Attribute {
                                    key: TendermintEventKey::EthBloom.to_base64_string(),
                                    value: encode(&[0; 256][..]),
                                }],
                            }],
                        }),
                    },
                })
            } else if height == 2 {
                Ok(BlockResults {
                    height: Height::default().increment(),
                    results: Results {
                        deliver_tx: Some(vec![DeliverTx {
                            events: vec![Event {
                                event_type: TendermintEventType::ValidTransactions.to_string(),
                                attributes: vec![
                                    Attribute {
                                        key: TendermintEventKey::TxId.to_base64_string(),
                                        value: encode(
                                            hex::encode(&unbond_transaction().tx_id()).as_bytes(),
                                        )
                                        .to_owned(),
                                    },
                                    Attribute {
                                        key: TendermintEventKey::Account.to_base64_string(),
                                        value: encode(&Vec::from(format!(
                                            "{}",
                                            &self.staking_address
                                        ))),
                                    },
                                ],
                            }],
                        }]),
                        end_block: Some(EndBlock { events: Vec::new() }),
                    },
                })
            } else {
                Err(ErrorKind::InvalidInput.into())
            }
        }

        fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            heights: T,
        ) -> Result<Vec<BlockResults>> {
            heights.map(|height| self.block_results(*height)).collect()
        }

        fn block_batch_verified<'a, T: Clone + Iterator<Item = &'a u64>>(
            &self,
            state: lite::TrustedState,
            heights: T,
        ) -> Result<(Vec<Block>, lite::TrustedState)> {
            Ok((self.block_batch(heights)?, state))
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<BroadcastTxResponse> {
            unreachable!()
        }

        fn query(&self, _path: &str, _data: &[u8]) -> Result<AbciQuery> {
            unreachable!()
        }

        fn query_state_batch<T: Iterator<Item = u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<ChainState>> {
            unreachable!()
        }
    }

    fn check_manual_synchronization_impl(enable_fast_forward: bool) {
        let storage = MemoryStorage::default();

        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let wallet = DefaultWalletClient::new_read_only(storage.clone());

        assert!(wallet
            .new_wallet(name, passphrase, WalletKind::Basic)
            .is_ok());

        let mut generator = BlockGenerator::one_node();
        for _ in 0..10 {
            generator.gen_block(&[]);
        }

        let synchronizer = ManualSynchronizer::new(
            storage.clone(),
            generator,
            MockBlockHandler,
            enable_fast_forward,
        );

        synchronizer
            .sync(name, passphrase, None, None)
            .expect("Unable to synchronize");
    }

    #[test]
    fn check_manual_synchronization() {
        check_manual_synchronization_impl(false);
        check_manual_synchronization_impl(true);
    }
}
