//! mock transaction obfuscator
use std::convert::TryInto;

use crate::tendermint::Client;
use crate::{PrivateKey, Result, SignedTransaction, Transaction};
use chain_core::tx::data::TxId;
use chain_core::tx::{TxAux, TxEnclaveAux, TxWithOutputs};
use mock_utils::{encrypt, unseal};

use crate::TransactionObfuscation;

/// Implementation of transaction cipher which uses Tendermint ABCI to encrypt/decrypt transactions
#[derive(Debug, Clone)]
pub struct MockAbciTransactionObfuscation<C>
where
    C: Client,
{
    client: C,
}

impl<C> MockAbciTransactionObfuscation<C>
where
    C: Client,
{
    /// Creates a new instance of `MockAbciTransactionObfuscation`
    #[inline]
    pub fn new(client: C) -> Self {
        Self { client }
    }
    /// Same constructor as `DefaultTransactionObfuscation`
    pub fn from_tx_query(client: &C) -> Result<Self> {
        Ok(Self::new(client.clone()))
    }
}

impl<C> TransactionObfuscation for MockAbciTransactionObfuscation<C>
where
    C: Client,
{
    fn decrypt(&self, txids: &[TxId], private_key: &PrivateKey) -> Result<Vec<Transaction>> {
        if txids.is_empty() {
            return Ok(vec![]);
        }

        let rsps = txids
            .iter()
            .map(|txid| self.client.query("sealed", txid, None, false))
            .collect::<Result<Vec<_>>>()
            .expect("abci_query failed");

        let sealed_logs = rsps.into_iter().map(|rsp| rsp.value);

        let txs = sealed_logs
            .into_iter()
            .filter_map(|sealed| checked_unseal(&sealed, private_key))
            .map(Transaction::from)
            .collect::<Vec<_>>();

        Ok(txs)
    }

    fn encrypt(&self, transaction: SignedTransaction) -> Result<TxAux> {
        let payload = encrypt(&transaction.clone().into(), transaction.tx_id());
        let enclave_tx = match transaction {
            SignedTransaction::TransferTransaction(tx, _) => TxEnclaveAux::TransferTx {
                inputs: tx.inputs.clone(),
                no_of_outputs: tx.outputs.len().try_into().unwrap(),
                payload,
            },
            SignedTransaction::DepositStakeTransaction(tx, _) => {
                TxEnclaveAux::DepositStakeTx { tx, payload }
            }
            SignedTransaction::WithdrawUnbondedStakeTransaction(tx, witness) => {
                TxEnclaveAux::WithdrawUnbondedStakeTx {
                    no_of_outputs: tx.outputs.len().try_into().unwrap(),
                    witness,
                    payload,
                }
            }
        };
        Ok(TxAux::EnclaveTx(enclave_tx))
    }
}

fn checked_unseal(payload: &[u8], _private_key: &PrivateKey) -> Option<TxWithOutputs> {
    let tx = unseal(payload).unwrap();
    // TODO check view key
    Some(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tendermint::types::*;
    use crate::PrivateKey;
    use chain_core::state::ChainState;
    use chain_core::tx::data::Tx;
    use chain_core::tx::witness::TxWitness;
    use chain_core::tx::{TxEnclaveAux, TxWithOutputs};
    use mock_utils::seal;

    #[derive(Clone)]
    struct MockClient;

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<StatusResponse> {
            unreachable!()
        }

        fn block(&self, _height: u64) -> Result<Block> {
            unreachable!()
        }

        fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, _heights: T) -> Result<Vec<Block>> {
            unreachable!()
        }

        fn block_results(&self, _height: u64) -> Result<BlockResultsResponse> {
            unreachable!()
        }

        fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<BlockResultsResponse>> {
            unreachable!()
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
            Ok(AbciQuery {
                value: seal(&TxWithOutputs::Transfer(Tx::default())),
                ..Default::default()
            })
        }

        fn query_state_batch<T: Iterator<Item = u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<ChainState>> {
            unreachable!()
        }
    }

    #[test]
    fn check_decryption() {
        let cipher = MockAbciTransactionObfuscation::new(MockClient);

        assert_eq!(
            1,
            cipher
                .decrypt(&[[0; 32]], &PrivateKey::new().unwrap())
                .unwrap()
                .len()
        )
    }

    #[test]
    fn check_encryption() {
        let cipher = MockAbciTransactionObfuscation::new(MockClient);

        let encrypted_transaction = cipher
            .encrypt(SignedTransaction::TransferTransaction(
                Tx::default(),
                TxWitness::default(),
            ))
            .unwrap();

        match encrypted_transaction {
            TxAux::EnclaveTx(TxEnclaveAux::TransferTx { no_of_outputs, .. }) => {
                assert_eq!(0, no_of_outputs)
            }
            _ => unreachable!(),
        }
    }
}
