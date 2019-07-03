use chrono::offset::Utc;
use chrono::DateTime;

use chain_core::init::coin::Coin;
use chain_core::state::account::{DepositBondTx, WithdrawUnbondedTx};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::{Tx, TxId};
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
    balance_service: BalanceService<S>,
    global_state_service: GlobalStateService<S>,
    transaction_change_service: TransactionChangeService<S>,
    transaction_service: TransactionService<S>,
    unspent_transaction_service: UnspentTransactionService<S>,
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
            balance_service: BalanceService::new(storage.clone()),
            global_state_service: GlobalStateService::new(storage.clone()),
            transaction_change_service: TransactionChangeService::new(storage.clone()),
            transaction_service: TransactionService::new(storage.clone()),
            unspent_transaction_service: UnspentTransactionService::new(storage),
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
        self.balance_service.clear()?;
        self.global_state_service.clear()?;
        self.transaction_change_service.clear()?;
        self.transaction_service.clear()
    }

    fn handle_transaction(
        &self,
        transaction: TxAux,
        height: u64,
        time: DateTime<Utc>,
    ) -> Result<()> {
        match transaction {
            TxAux::TransferTx(transfer_transaction, _) => {
                self.handle_transfer_transaction(&transfer_transaction, height, time)?;
                self.transaction_service.set(
                    &transfer_transaction.id(),
                    &Transaction::TransferTransaction(transfer_transaction),
                )
            }
            TxAux::DepositStakeTx(deposit_bond_transaction, _) => {
                self.handle_deposit_stake_transaction(&deposit_bond_transaction, height, time)?;
                self.transaction_service.set(
                    &deposit_bond_transaction.id(),
                    &Transaction::DepositStakeTransaction(deposit_bond_transaction),
                )
            }
            TxAux::UnbondStakeTx(unbond_transaction, _) => self.transaction_service.set(
                &unbond_transaction.id(),
                &Transaction::UnbondStakeTransaction(unbond_transaction),
            ),
            TxAux::WithdrawUnbondedStakeTx(withdraw_unbonded_transaction, _) => {
                self.handle_withdraw_unbonded_stake_transaction(
                    &withdraw_unbonded_transaction,
                    height,
                    time,
                )?;
                self.transaction_service.set(
                    &withdraw_unbonded_transaction.id(),
                    &Transaction::WithdrawUnbondedStakeTransaction(withdraw_unbonded_transaction),
                )
            }
        }
    }

    fn handle_transfer_transaction(
        &self,
        transaction: &Tx,
        height: u64,
        time: DateTime<Utc>,
    ) -> Result<()> {
        let transaction_id = transaction.id();

        for input in transaction.inputs.iter() {
            self.handle_transaction_input(transaction_id, input, height, time)?;
        }

        for (i, output) in transaction.outputs.iter().enumerate() {
            self.handle_transaction_output(transaction_id, output, i, height, time)?;
        }

        Ok(())
    }

    fn handle_deposit_stake_transaction(
        &self,
        transaction: &DepositBondTx,
        height: u64,
        time: DateTime<Utc>,
    ) -> Result<()> {
        let transaction_id = transaction.id();

        for input in transaction.inputs.iter() {
            self.handle_transaction_input(transaction_id, input, height, time)?;
        }

        Ok(())
    }

    fn handle_withdraw_unbonded_stake_transaction(
        &self,
        transaction: &WithdrawUnbondedTx,
        height: u64,
        time: DateTime<Utc>,
    ) -> Result<()> {
        let transaction_id = transaction.id();

        for (i, output) in transaction.outputs.iter().enumerate() {
            self.handle_transaction_output(transaction_id, output, i, height, time)?;
        }

        Ok(())
    }

    fn handle_transaction_input(
        &self,
        transaction_id: TxId,
        input: &TxoPointer,
        height: u64,
        time: DateTime<Utc>,
    ) -> Result<()> {
        let output = self.output(&input.id, input.index as usize)?;

        let change = TransactionChange {
            transaction_id,
            address: output.address,
            balance_change: BalanceChange::Outgoing(output.value),
            height,
            time,
        };

        // Update balance
        self.balance_service
            .change(&change.address, &change.balance_change)?;

        // Update unspent transactions
        self.unspent_transaction_service
            .remove(&change.address, input)?;

        // Update transaction history
        self.transaction_change_service.add(&change)
    }

    fn handle_transaction_output(
        &self,
        transaction_id: TxId,
        output: &TxOut,
        index: usize,
        height: u64,
        time: DateTime<Utc>,
    ) -> Result<()> {
        let change = TransactionChange {
            transaction_id,
            address: output.address.clone(),
            balance_change: BalanceChange::Incoming(output.value),
            height,
            time,
        };

        // Update balance
        self.balance_service
            .change(&change.address, &change.balance_change)?;

        // Update unspent transactions
        self.unspent_transaction_service.add(
            &change.address,
            (&TxoPointer::new(transaction_id, index), output),
        )?;

        // Update transaction history
        self.transaction_change_service.add(&change)
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
            let valid_transaction_ids = self.client.block_results(height)?.ids()?;
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
        self.transaction_change_service.get(address)
    }

    #[inline]
    fn balance(&self, address: &ExtendedAddr) -> Result<Coin> {
        self.balance_service.get(address)
    }

    #[inline]
    fn unspent_transactions(&self, address: &ExtendedAddr) -> Result<Vec<(TxoPointer, TxOut)>> {
        self.unspent_transaction_service.get(address)
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

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::state::account::StakedStateOpWitness;
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::attribute::TxAttributes;
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
                addresses: [
                    ExtendedAddr::BasicRedeem(
                        RedeemAddress::from_str("1fdf22497167a793ca794963ad6c95e6ffa0b971")
                            .unwrap(),
                    ),
                    ExtendedAddr::BasicRedeem(
                        RedeemAddress::from_str("790661a2fd9da3fee53caab80859ecae125a20a5")
                            .unwrap(),
                    ),
                ],
            }
        }
    }

    impl MockClient {
        fn transaction(&self, height: u64) -> Option<TxAux> {
            if height == 1 {
                Some(TxAux::WithdrawUnbondedStakeTx(
                    WithdrawUnbondedTx {
                        nonce: 0,
                        outputs: vec![TxOut {
                            address: self.addresses[0].clone(),
                            value: Coin::new(100).unwrap(),
                            valid_from: None,
                        }],
                        attributes: TxAttributes::new(171),
                    },
                    StakedStateOpWitness::new(
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
                ))
            } else if height == 2 {
                Some(TxAux::TransferTx(
                    Tx {
                        inputs: vec![TxoPointer {
                            id: self.transaction(1).unwrap().tx_id(),
                            index: 0,
                        }],
                        outputs: vec![TxOut {
                            address: self.addresses[1].clone(),
                            value: Coin::new(100).unwrap(),
                            valid_from: None,
                        }],
                        attributes: TxAttributes::new(171),
                    },
                    vec![].into(),
                ))
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
                            tags: vec![Tag {
                                key: "dHhpZA==".to_owned(),
                                value: base64::encode(&self.transaction(1).unwrap().tx_id()[..]),
                            }],
                        }]),
                    },
                })
            } else if height == 2 {
                Ok(BlockResults {
                    height: "2".to_owned(),
                    results: Results {
                        deliver_tx: Some(vec![DeliverTx {
                            tags: vec![Tag {
                                key: "dHhpZA==".to_owned(),
                                value: base64::encode(&self.transaction(2).unwrap().tx_id()[..]),
                            }],
                        }]),
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
        fn query(&self, _path: &str, _data: &str) -> Result<QueryResult> {
            Ok(QueryResult {
                response: Response {
                    value: "".to_string(),
                },
            })
        }
    }

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
