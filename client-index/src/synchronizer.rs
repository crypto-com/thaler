//! Utilities for synchronizing transaction index with Crypto.com Chain
use std::sync::mpsc::Sender;

use itertools::Itertools;

use chain_core::state::account::StakedStateAddress;
use chain_tx_filter::BlockFilter;
use client_common::tendermint::types::{Block, BlockResults, Status};
use client_common::tendermint::Client;
use client_common::{BlockHeader, PrivateKey, PublicKey, Result, Storage, Transaction};

use crate::service::GlobalStateService;
use crate::BlockHandler;

const DEFAULT_BATCH_SIZE: usize = 20;

/// A struct for providing progress report for synchronization
#[derive(Debug)]
pub enum ProgressReport {
    /// Initial report to send start/finish heights
    Init {
        /// Block height from which synchronization started
        start_block_height: u64,
        /// Block height at which synchronization will finish
        finish_block_height: u64,
    },
    /// Report to update progress status
    Update {
        /// Current synchronized block height
        current_block_height: u64,
    },
}

/// Synchronizer for transaction index which can be triggered manually
pub struct ManualSynchronizer<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    global_state_service: GlobalStateService<S>,
    client: C,
    block_handler: H,
}

impl<S, C, H> ManualSynchronizer<S, C, H>
where
    S: Storage,
    C: Client,
    H: BlockHandler,
{
    /// Creates a new instance of `ManualSynchronizer`
    #[inline]
    pub fn new(storage: S, client: C, block_handler: H) -> Self {
        Self {
            global_state_service: GlobalStateService::new(storage),
            client,
            block_handler,
        }
    }

    /// Synchronizes transaction index for given view key with Crypto.com Chain (from last known height)
    pub fn sync(
        &self,
        staking_addresses: &[StakedStateAddress],
        view_key: &PublicKey,
        private_key: &PrivateKey,
        batch_size: Option<usize>,
        progress_reporter: Option<Sender<ProgressReport>>,
    ) -> Result<()> {
        let status = self.client.status()?;

        let last_block_height = self.global_state_service.last_block_height(view_key)?;
        let current_block_height = status.last_block_height()?;

        if let Some(ref sender) = &progress_reporter {
            let _ = sender.send(ProgressReport::Init {
                start_block_height: last_block_height,
                finish_block_height: current_block_height,
            });
        }

        // Send batch RPC requests to tendermint in chunks of `batch_size` requests per batch call
        for chunk in ((last_block_height + 1)..=current_block_height)
            .chunks(batch_size.unwrap_or(DEFAULT_BATCH_SIZE))
            .into_iter()
        {
            if self.fast_forward_status(
                staking_addresses,
                view_key,
                private_key,
                &status,
                &progress_reporter,
            )? {
                // Fast forward to latest state if possible
                return Ok(());
            }

            let range = chunk.collect::<Vec<u64>>();

            // Get the last block to check if there are any changes
            let block = self.client.block(range[range.len() - 1])?;
            if self.fast_forward_block(
                staking_addresses,
                view_key,
                private_key,
                &block,
                &progress_reporter,
            )? {
                // Fast forward batch if possible
                continue;
            }

            // Fetch batch details if it cannot be fast forwarded
            let blocks = self.client.block_batch(range.iter())?;
            let block_results = self.client.block_results_batch(range.iter())?;

            for (block, block_result) in blocks.into_iter().zip(block_results.into_iter()) {
                if self.fast_forward_status(
                    staking_addresses,
                    view_key,
                    private_key,
                    &status,
                    &progress_reporter,
                )? {
                    // Fast forward to latest state if possible
                    return Ok(());
                }

                let block_header = prepare_block_header(staking_addresses, &block, &block_result)?;
                self.block_handler
                    .on_next(block_header, view_key, private_key)?;

                if let Some(ref sender) = &progress_reporter {
                    let _ = sender.send(ProgressReport::Update {
                        current_block_height: block.height()?,
                    });
                }
            }
        }

        Ok(())
    }

    /// Synchronizes transaction index for given view key with Crypto.com Chain (from genesis)
    #[inline]
    pub fn sync_all(
        &self,
        staking_addresses: &[StakedStateAddress],
        view_key: &PublicKey,
        private_key: &PrivateKey,
        batch_size: Option<usize>,
        progress_reporter: Option<Sender<ProgressReport>>,
    ) -> Result<()> {
        self.global_state_service
            .set_global_state(view_key, 0, "".to_string())?;
        self.sync(
            staking_addresses,
            view_key,
            private_key,
            batch_size,
            progress_reporter,
        )
    }

    /// Fast forwards state to given status if app hashes match
    fn fast_forward_status(
        &self,
        staking_addresses: &[StakedStateAddress],
        view_key: &PublicKey,
        private_key: &PrivateKey,
        status: &Status,
        progress_reporter: &Option<Sender<ProgressReport>>,
    ) -> Result<bool> {
        let last_app_hash = self.global_state_service.last_app_hash(view_key)?;
        let current_app_hash = status.last_app_hash();

        if current_app_hash == last_app_hash {
            let current_block_height = status.last_block_height()?;

            let block = self.client.block(current_block_height)?;
            let block_result = self.client.block_results(current_block_height)?;

            let block_header = prepare_block_header(staking_addresses, &block, &block_result)?;
            self.block_handler
                .on_next(block_header, view_key, private_key)?;

            if let Some(ref sender) = progress_reporter {
                let _ = sender.send(ProgressReport::Update {
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
        staking_addresses: &[StakedStateAddress],
        view_key: &PublicKey,
        private_key: &PrivateKey,
        block: &Block,
        progress_reporter: &Option<Sender<ProgressReport>>,
    ) -> Result<bool> {
        let last_app_hash = self.global_state_service.last_app_hash(view_key)?;
        let current_app_hash = block.app_hash();

        if current_app_hash == last_app_hash {
            let current_block_height = block.height()?;

            let block_result = self.client.block_results(current_block_height)?;

            let block_header = prepare_block_header(staking_addresses, &block, &block_result)?;
            self.block_handler
                .on_next(block_header, view_key, private_key)?;

            if let Some(ref sender) = progress_reporter {
                let _ = sender.send(ProgressReport::Update {
                    current_block_height,
                });
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn check_unencrypted_transactions(
    block_filter: &BlockFilter,
    staking_addresses: &[StakedStateAddress],
    block: &Block,
) -> Result<Vec<Transaction>> {
    for staking_address in staking_addresses {
        if block_filter.check_staked_state_address(staking_address) {
            return block.unencrypted_transactions();
        }
    }

    Ok(Default::default())
}

fn prepare_block_header(
    staking_addresses: &[StakedStateAddress],
    block: &Block,
    block_result: &BlockResults,
) -> Result<BlockHeader> {
    let app_hash = block.app_hash();
    let block_height = block.height()?;
    let block_time = block.time();

    let transaction_ids = block_result.transaction_ids()?;
    let block_filter = block_result.block_filter()?;

    let unencrypted_transactions =
        check_unencrypted_transactions(&block_filter, staking_addresses, block)?;

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
    use chrono::DateTime;
    use parity_scale_codec::Encode;
    use secp256k1::recovery::{RecoverableSignature, RecoveryId};

    use chain_core::common::TendermintEventType;
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::state::account::{StakedStateOpAttributes, StakedStateOpWitness, UnbondTx};
    use chain_core::tx::TxAux;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;
    use client_common::ErrorKind;

    fn unbond_transaction() -> TxAux {
        TxAux::UnbondStakeTx(
            UnbondTx::new(Coin::new(100).unwrap(), 0, StakedStateOpAttributes::new(0)),
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
            _block_header: BlockHeader,
            _view_key: &PublicKey,
            _private_key: &PrivateKey,
        ) -> Result<()> {
            Ok(())
        }
    }

    struct MockClient {
        staking_address: StakedStateAddress,
    }

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<Status> {
            Ok(Status {
                sync_info: SyncInfo {
                    latest_block_height: "2".to_owned(),
                    latest_app_hash:
                        "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C"
                            .to_string(),
                },
            })
        }

        fn block(&self, height: u64) -> Result<Block> {
            if height == 1 {
                Ok(Block {
                    block: BlockInner {
                        header: Header {
                            app_hash:
                                "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3D"
                                    .to_string(),
                            height: "1".to_owned(),
                            time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                        },
                        data: Data { txs: None },
                    },
                })
            } else if height == 2 {
                Ok(Block {
                    block: BlockInner {
                        header: Header {
                            app_hash:
                                "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C"
                                    .to_string(),
                            height: "2".to_owned(),
                            time: DateTime::from_str("2019-04-10T09:38:41.735577Z").unwrap(),
                        },
                        data: Data {
                            txs: Some(vec![encode(&unbond_transaction().encode())]),
                        },
                    },
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
                    height: "1".to_string(),
                    results: Results {
                        deliver_tx: None,
                        end_block: Some(EndBlock {
                            events: vec![Event {
                                event_type: TendermintEventType::BlockFilter.to_string(),
                                attributes: vec![Attribute {
                                    key: "ethbloom".to_owned(),
                                    value: encode(&[0; 256][..]),
                                }],
                            }],
                        }),
                    },
                })
            } else if height == 2 {
                let mut block_filter = BlockFilter::default();
                block_filter.add_staked_state_address(&self.staking_address);

                Ok(BlockResults {
                    height: "2".to_string(),
                    results: Results {
                        deliver_tx: Some(vec![DeliverTx {
                            events: vec![Event {
                                event_type: TendermintEventType::ValidTransactions.to_string(),
                                attributes: vec![Attribute {
                                    key: "dHhpZA==".to_owned(),
                                    value: encode(
                                        hex::encode(&unbond_transaction().tx_id()).as_bytes(),
                                    )
                                    .to_owned(),
                                }],
                            }],
                        }]),
                        end_block: Some(EndBlock {
                            events: vec![Event {
                                event_type: TendermintEventType::BlockFilter.to_string(),
                                attributes: vec![Attribute {
                                    key: "ethbloom".to_owned(),
                                    value: encode(&block_filter.get_tendermint_kv().unwrap().1),
                                }],
                            }],
                        }),
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

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<BroadcastTxResult> {
            unreachable!()
        }

        fn query(&self, _path: &str, _data: &[u8]) -> Result<QueryResult> {
            unreachable!()
        }
    }

    #[test]
    fn check_manual_synchronization() {
        let storage = MemoryStorage::default();

        let private_key = PrivateKey::new().unwrap();
        let view_key = PublicKey::from(&private_key);
        let staking_address = StakedStateAddress::BasicRedeem(RedeemAddress::from(&view_key));

        let synchronizer = ManualSynchronizer::new(
            storage.clone(),
            MockClient { staking_address },
            MockBlockHandler,
        );

        synchronizer
            .sync(&[staking_address], &view_key, &private_key, None, None)
            .expect("Unable to synchronize");
    }
}
