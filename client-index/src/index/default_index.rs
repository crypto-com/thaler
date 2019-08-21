use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use client_common::tendermint::Client;
use client_common::{Result, Storage, Transaction};

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
    #[inline]
    pub fn new(storage: S, client: C) -> Self {
        Self {
            address_service: AddressService::new(storage.clone()),
            global_state_service: GlobalStateService::new(storage.clone()),
            transaction_service: TransactionService::new(storage),
            client,
        }
    }
}

impl<S, C> Index for DefaultIndex<S, C>
where
    S: Storage,
    C: Client,
{
    #[inline]
    fn address_details(&self, address: &ExtendedAddr) -> Result<AddressDetails> {
        self.address_service.get(address)
    }

    #[inline]
    fn transaction(&self, id: &TxId) -> Result<Option<Transaction>> {
        self.transaction_service.get(id)
    }

    #[inline]
    fn output(&self, input: &TxoPointer) -> Result<TxOut> {
        self.transaction_service.get_output(input)
    }

    #[inline]
    fn broadcast_transaction(&self, transaction: &[u8]) -> Result<()> {
        self.client.broadcast_transaction(transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chain_core::init::coin::Coin;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;
    use client_common::ErrorKind;

    struct MockClient;

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<Status> {
            unreachable!()
        }

        fn block(&self, _height: u64) -> Result<Block> {
            unreachable!()
        }

        fn block_batch<T: Iterator<Item = u64>>(&self, _heights: T) -> Result<Vec<Block>> {
            unreachable!()
        }

        fn block_results(&self, _height: u64) -> Result<BlockResults> {
            unreachable!()
        }

        fn block_results_batch<T: Iterator<Item = u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<BlockResults>> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<()> {
            Ok(())
        }

        fn query(&self, _path: &str, _data: &[u8]) -> Result<QueryResult> {
            unreachable!()
        }
    }

    #[test]
    fn check_index() {
        let storage = MemoryStorage::default();
        let index = DefaultIndex::new(storage, MockClient);

        let address = ExtendedAddr::OrTree([0; 32]);

        assert_eq!(
            Coin::zero(),
            index.address_details(&address).unwrap().balance
        );
        assert_eq!(None, index.transaction(&[0; 32]).unwrap());
        assert_eq!(
            ErrorKind::TransactionNotFound,
            index
                .output(&TxoPointer::new([0; 32], 0))
                .unwrap_err()
                .kind()
        );
        assert!(index.broadcast_transaction(&[0; 32]).is_ok());
    }
}
