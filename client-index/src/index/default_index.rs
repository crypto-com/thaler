use chrono::offset::Utc;
use chrono::DateTime;

use chain_core::init::coin::Coin;
use chain_core::state::account::DepositBondTx;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use chain_core::tx::TransactionId;
use chain_core::tx::TxAux;
use client_common::balance::{BalanceChange, TransactionChange};
use client_common::tendermint::Client;
use client_common::{Error, ErrorKind, Result, Storage, Transaction};

use crate::service::*;
use crate::Index;

/// Default implementation of transaction index using `Storage` and `TendermintClient`
#[derive(Default, Clone)]
pub struct DefaultIndex<S, C>
where
    S: Storage,
    C: Client,
{
    address_service: AddressService<S>,
    global_state_service: GlobalStateService<S>,
    transaction_service: TransactionService<S>,
    client: C,
}

impl<S, C> DefaultIndex<S, C>
where
    S: Storage + Clone,
    C: Client,
{
    /// Creates a new instance of `DefaultIndex`
    pub fn new(storage: S, client: C) -> Self {
        Self {
            address_service: AddressService::new(storage.clone()),
            global_state_service: GlobalStateService::new(storage.clone()),
            transaction_service: TransactionService::new(storage),
            client,
        }
    }
}

impl<S, C> DefaultIndex<S, C>
where
    S: Storage,
    C: Client,
{
    /// Clears all the services
    fn clear(&self) -> Result<()> {
        self.address_service.clear()?;
        self.global_state_service.clear()?;
        self.transaction_service.clear()
    }

    fn handle_transaction(
        &self,
        transaction: TxAux,
        height: u64,
        time: DateTime<Utc>,
    ) -> Result<()> {
        match transaction {
            TxAux::TransferTx {..} => {
                unimplemented!("FIXME: indexing should be rethought, as it'll first check the filter and query (block data would be obfuscated)")
            }
            TxAux::DepositStakeTx{ tx, .. } => {
                self.handle_deposit_stake_transaction(tx.clone(), height, time)?;
                self.transaction_service.set(
                    &Transaction::DepositStakeTransaction(tx),
                )
            }
            TxAux::UnbondStakeTx(unbond_transaction, _) => self.transaction_service.set(
                &Transaction::UnbondStakeTransaction(unbond_transaction),
            ),
            TxAux::WithdrawUnbondedStakeTx{ .. } => {
                unimplemented!("FIXME: indexing should be rethought, as it'll first check the filter and query (block data would be obfuscated)")
            }
        }
    }

    fn handle_deposit_stake_transaction(
        &self,
        transaction: DepositBondTx,
        height: u64,
        time: DateTime<Utc>,
    ) -> Result<()> {
        let transaction_id = transaction.id();
        let mut memento = AddressMemento::new(transaction_id);

        for input in transaction.inputs.into_iter() {
            self.handle_transaction_input(&mut memento, transaction_id, input, height, time)?;
        }

        self.address_service.apply_memento(&memento)
    }

    fn handle_transaction_input(
        &self,
        memento: &mut AddressMemento,
        transaction_id: TxId,
        input: TxoPointer,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) -> Result<()> {
        let output = self.transaction_service.get_output(&input)?;

        let change = TransactionChange {
            transaction_id,
            address: output.address,
            balance_change: BalanceChange::Outgoing(output.value),
            block_height,
            block_time,
        };

        let address = change.address.clone();

        // Update transaction history and balance
        memento.add_transaction_change(&address, change);

        // Update unspent transactions
        memento.remove_unspent_transaction(&address, input);

        Ok(())
    }

    /// this will still be probably used even in redesigned client indexing
    #[allow(dead_code)]
    fn handle_transaction_output(
        &self,
        memento: &mut AddressMemento,
        transaction_id: TxId,
        output: TxOut,
        index: usize,
        block_height: u64,
        block_time: DateTime<Utc>,
    ) {
        let change = TransactionChange {
            transaction_id,
            address: output.address.clone(),
            balance_change: BalanceChange::Incoming(output.value),
            block_height,
            block_time,
        };

        let address = change.address.clone();

        // Update transaction history and balance
        memento.add_transaction_change(&address, change);

        // Update unspent transactions
        memento.add_unspent_transaction(&address, TxoPointer::new(transaction_id, index), output);
    }
}

impl<S, C> Index for DefaultIndex<S, C>
where
    S: Storage,
    C: Client,
{
    fn sync(&self) -> Result<()> {
        let last_block_height = self
            .global_state_service
            .last_block_height()?
            .unwrap_or_default();

        let current_block_height = self.client.status()?.last_block_height()?;

        for height in (last_block_height + 1)..=current_block_height {
            let valid_transaction_ids = self.client.block_results(height)?.transaction_ids()?;
            let block = self.client.block(height)?;
            let transactions = block.transactions()?;

            for transaction in transactions {
                let transaction_id = transaction.tx_id();

                if valid_transaction_ids.contains(&transaction_id) {
                    self.handle_transaction(transaction, height, block.time())?;
                }
            }

            self.global_state_service.set_last_block_height(height)?;
        }

        Ok(())
    }

    #[inline]
    fn sync_all(&self) -> Result<()> {
        self.clear()?;
        self.sync()
    }

    #[inline]
    fn transaction_changes(&self, address: &ExtendedAddr) -> Result<Vec<TransactionChange>> {
        Ok(self.address_service.get(address)?.transaction_history)
    }

    #[inline]
    fn balance(&self, address: &ExtendedAddr) -> Result<Coin> {
        Ok(self.address_service.get(address)?.balance)
    }

    #[inline]
    fn unspent_transactions(&self, address: &ExtendedAddr) -> Result<Vec<(TxoPointer, TxOut)>> {
        Ok(self.address_service.get(address)?.unspent_transactions)
    }

    #[inline]
    fn transaction(&self, id: &TxId) -> Result<Option<Transaction>> {
        self.transaction_service.get(id)
    }

    fn output(&self, id: &TxId, index: usize) -> Result<TxOut> {
        let transaction = self
            .transaction(id)?
            .ok_or_else(|| Error::from(ErrorKind::TransactionNotFound))?;

        match transaction {
            Transaction::TransferTransaction(transfer_transaction) => {
                let output = transfer_transaction
                    .outputs
                    .into_iter()
                    .nth(index)
                    .ok_or_else(|| Error::from(ErrorKind::TransactionNotFound))?;

                Ok(output)
            }
            Transaction::WithdrawUnbondedStakeTransaction(withdraw_transaction) => {
                let output = withdraw_transaction
                    .outputs
                    .into_iter()
                    .nth(index)
                    .ok_or_else(|| Error::from(ErrorKind::TransactionNotFound))?;

                Ok(output)
            }
            _ => Err(ErrorKind::InvalidTransaction.into()),
        }
    }

    #[inline]
    fn broadcast_transaction(&self, transaction: &[u8]) -> Result<()> {
        self.client.broadcast_transaction(transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use chrono::DateTime;
    use parity_codec::Encode;
    use secp256k1::recovery::{RecoverableSignature, RecoveryId};

    use chain_core::common::TendermintEventType;
    use chain_core::init::coin::Coin;
    use chain_core::state::account::StakedStateOpWitness;
    use chain_core::state::account::WithdrawUnbondedTx;
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::attribute::TxAttributes;
    use chain_core::tx::data::Tx;
    use chain_core::tx::PlainTxAux;
    use chain_core::tx::TxObfuscated;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;

    /// Mock tendermint client
    #[derive(Clone)]
    pub struct MockClient {
        pub addresses: [ExtendedAddr; 2],
    }

    impl Default for MockClient {
        fn default() -> Self {
            Self {
                addresses: [ExtendedAddr::OrTree([0; 32]), ExtendedAddr::OrTree([1; 32])],
            }
        }
    }

    impl MockClient {
        fn transaction(&self, height: u64) -> Option<TxAux> {
            if height == 1 {
                let withdrawtx = WithdrawUnbondedTx {
                    nonce: 0,
                    outputs: vec![TxOut {
                        address: self.addresses[0].clone(),
                        value: Coin::new(100).unwrap(),
                        valid_from: None,
                    }],
                    attributes: TxAttributes::new(171),
                };

                // FIXME: mock enc
                Some(TxAux::WithdrawUnbondedStakeTx {
                    txid: withdrawtx.id(),
                    no_of_outputs: 1,
                    witness: StakedStateOpWitness::new(
                        RecoverableSignature::from_compact(
                            &[
                                0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f, 0x04, 0x77, 0x2b,
                                0x6f, 0x92, 0x1f, 0x0b, 0xa6, 0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43,
                                0x9e, 0x65, 0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98, 0x4c,
                                0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8, 0x80, 0x12, 0x0e, 0xf8,
                                0x02, 0x5e, 0x70, 0x9f, 0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae,
                                0x06, 0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89,
                            ],
                            RecoveryId::from_i32(1).unwrap(),
                        )
                        .unwrap(),
                    ),
                    payload: TxObfuscated {
                        key_from: 0,
                        nonce: [0u8; 12],
                        txpayload: PlainTxAux::WithdrawUnbondedStakeTx(withdrawtx).encode(),
                    },
                })
            } else if height == 2 {
                let inputs = vec![TxoPointer {
                    id: self.transaction(1).unwrap().tx_id(),
                    index: 0,
                }];
                let tx = Tx {
                    inputs: inputs.clone(),
                    outputs: vec![TxOut {
                        address: self.addresses[1].clone(),
                        value: Coin::new(100).unwrap(),
                        valid_from: None,
                    }],
                    attributes: TxAttributes::new(171),
                };
                Some(TxAux::TransferTx {
                    txid: tx.id(),
                    inputs,
                    no_of_outputs: 1,
                    payload: TxObfuscated {
                        key_from: 0,
                        nonce: [0u8; 12],
                        txpayload: PlainTxAux::TransferTx(tx.clone(), vec![].into()).encode(),
                    },
                })
            } else {
                None
            }
        }
    }

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<Status> {
            Ok(Status {
                sync_info: SyncInfo {
                    latest_block_height: "2".to_owned(),
                },
            })
        }

        fn block(&self, height: u64) -> Result<Block> {
            if height == 1 {
                Ok(Block {
                    block: BlockInner {
                        header: Header {
                            height: "1".to_owned(),
                            time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                        },
                        data: Data {
                            txs: Some(vec![base64::encode(&self.transaction(1).unwrap().encode())]),
                        },
                    },
                })
            } else if height == 2 {
                Ok(Block {
                    block: BlockInner {
                        header: Header {
                            height: "2".to_owned(),
                            time: DateTime::from_str("2019-04-10T09:38:41.735577Z").unwrap(),
                        },
                        data: Data {
                            txs: Some(vec![base64::encode(&self.transaction(2).unwrap().encode())]),
                        },
                    },
                })
            } else {
                Err(ErrorKind::InvalidInput.into())
            }
        }

        fn block_results(&self, height: u64) -> Result<BlockResults> {
            if height == 1 {
                Ok(BlockResults {
                    height: "1".to_owned(),
                    results: Results {
                        deliver_tx: Some(vec![DeliverTx {
                            events: vec![Event {
                                event_type: TendermintEventType::ValidTransactions.to_string(),
                                attributes: vec![Attribute {
                                    key: "dHhpZA==".to_owned(),
                                    value: base64::encode(
                                        &self.transaction(1).unwrap().tx_id()[..],
                                    ),
                                }],
                            }],
                        }]),
                        end_block: None,
                    },
                })
            } else if height == 2 {
                Ok(BlockResults {
                    height: "2".to_owned(),
                    results: Results {
                        deliver_tx: Some(vec![DeliverTx {
                            events: vec![Event {
                                event_type: TendermintEventType::ValidTransactions.to_string(),
                                attributes: vec![Attribute {
                                    key: "dHhpZA==".to_owned(),
                                    value: base64::encode(
                                        &self.transaction(2).unwrap().tx_id()[..],
                                    ),
                                }],
                            }],
                        }]),
                        end_block: None,
                    },
                })
            } else {
                Err(ErrorKind::InvalidInput.into())
            }
        }

        fn broadcast_transaction(&self, _: &[u8]) -> Result<()> {
            Ok(())
        }

        /// Get abci query
        fn query(&self, _path: &str, _data: &[u8]) -> Result<QueryResult> {
            Ok(QueryResult {
                response: Response {
                    value: "".to_string(),
                },
            })
        }
    }

    // FIXME: !!!
    #[ignore]
    #[test]
    fn check_flow() {
        let client = MockClient::default();
        let storage = MemoryStorage::default();

        let index = DefaultIndex::new(storage, client.clone());

        assert!(index.sync_all().is_ok());

        assert_eq!(Coin::zero(), index.balance(&client.addresses[0]).unwrap());
        assert_eq!(
            Coin::new(100).unwrap(),
            index.balance(&client.addresses[1]).unwrap()
        );

        assert_eq!(
            0,
            index
                .unspent_transactions(&client.addresses[0])
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            index
                .unspent_transactions(&client.addresses[1])
                .unwrap()
                .len()
        );

        assert_eq!(
            2,
            index
                .transaction_changes(&client.addresses[0])
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            index
                .transaction_changes(&client.addresses[1])
                .unwrap()
                .len()
        );

        for change in index
            .transaction_changes(&client.addresses[0])
            .unwrap()
            .iter()
        {
            assert!(index.transaction(&change.transaction_id).unwrap().is_some());
            assert!(index.output(&change.transaction_id, 0).is_ok());
        }
    }
}
