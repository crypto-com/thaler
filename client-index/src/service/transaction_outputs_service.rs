use rlp::{decode_list, encode_list};

use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use client_common::{Result, Storage};

const KEYSPACE: &str = "index_transaction_outputs";

/// Exposes functionalities for managing transaction outputs
///
/// Stores `tx_id -> [tx_outputs]` mapping
#[derive(Default, Clone)]
pub struct TransactionOutputsService<S: Storage> {
    storage: S,
}

impl<S> TransactionOutputsService<S>
where
    S: Storage,
{
    /// Creates a new instance of transaction outputs service
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Retrieves transaction outputs corresponding to given transaction id
    pub fn get(&self, id: &TxId) -> Result<Vec<TxOut>> {
        let bytes = self.storage.get(KEYSPACE, id)?;

        match bytes {
            None => Ok(Default::default()),
            Some(bytes) => Ok(decode_list(&bytes)),
        }
    }

    /// Sets transaction outputs for given transaction id
    pub fn set(&self, id: &TxId, outputs: &[TxOut]) -> Result<()> {
        self.storage.set(KEYSPACE, id, encode_list(outputs))?;

        Ok(())
    }

    /// Clears all storage
    pub fn clear(&self) -> Result<()> {
        self.storage.clear(KEYSPACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chain_core::init::coin::Coin;
    use chain_core::tx::data::address::ExtendedAddr;
    use client_common::storage::MemoryStorage;

    #[test]
    fn check_flow() {
        let transaction_outputs_service = TransactionOutputsService::new(MemoryStorage::default());
        let id = TxId::zero();
        let outputs = vec![TxOut {
            address: ExtendedAddr::BasicRedeem(Default::default()),
            value: Coin::zero(),
            valid_from: None,
        }];

        assert_eq!(0, transaction_outputs_service.get(&id).unwrap().len());
        assert!(transaction_outputs_service.set(&id, &outputs).is_ok());
        assert_eq!(1, transaction_outputs_service.get(&id).unwrap().len());
        assert!(transaction_outputs_service.clear().is_ok());
        assert_eq!(0, transaction_outputs_service.get(&id).unwrap().len());
    }
}
