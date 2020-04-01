use parity_scale_codec::{Decode, Encode};

use chain_core::tx::data::TxId;
use chain_core::tx::{TxAux, TxWithOutputs};
use client_common::tendermint::types::AbciQueryExt;
use client_common::tendermint::Client;
use client_common::{
    Error, ErrorKind, PrivateKey, Result, ResultExt, SignedTransaction, Transaction, SECP,
};
use enclave_protocol::{
    DecryptionRequest, DecryptionResponse, EncryptionRequest, EncryptionResponse,
};

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

    fn encrypt_request(&self, encryption_request: EncryptionRequest) -> Result<TxAux> {
        let response = self
            .client
            .query("mockencrypt", &encryption_request.encode())?
            .bytes()?;

        let encrypted_transaction = EncryptionResponse::decode(&mut response.as_slice())
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to deserialize response of mock-encrypt ABCI call",
                )
            })?
            .resp
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid transaction was submitted: {}", e),
                )
            })?;

        Ok(TxAux::EnclaveTx(encrypted_transaction))
    }
}

impl<C> TransactionObfuscation for MockAbciTransactionObfuscation<C>
where
    C: Client,
{
    fn decrypt(
        &self,
        transaction_ids: &[TxId],
        private_key: &PrivateKey,
    ) -> Result<Vec<Transaction>> {
        if transaction_ids.is_empty() {
            return Ok(vec![]);
        }
        let request = SECP.with(|secp| {
            DecryptionRequest::create(
                &secp,
                transaction_ids.to_owned(),
                [0u8; 32],
                &private_key.into(),
            )
        });

        let response = self
            .client
            .query("mockdecrypt", &request.encode())?
            .bytes()?;

        let txs = DecryptionResponse::decode(&mut response.as_slice())
            .chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to deserialize response of mock-decrypt ABCI call",
                )
            })?
            .txs;

        let transactions = txs
            .into_iter()
            .map(|tx| match tx {
                TxWithOutputs::Transfer(t) => Transaction::TransferTransaction(t),
                TxWithOutputs::StakeWithdraw(t) => Transaction::WithdrawUnbondedStakeTransaction(t),
            })
            .collect::<Vec<Transaction>>();

        Ok(transactions)
    }

    fn encrypt(&self, transaction: SignedTransaction) -> Result<TxAux> {
        match transaction {
            SignedTransaction::TransferTransaction(tx, witness) => {
                self.encrypt_request(EncryptionRequest::TransferTx(tx, witness))
            }
            SignedTransaction::DepositStakeTransaction(tx, witness) => {
                self.encrypt_request(EncryptionRequest::DepositStake(tx, witness))
            }

            SignedTransaction::WithdrawUnbondedStakeTransaction(tx, state, witness) => {
                self.encrypt_request(EncryptionRequest::WithdrawStake(tx, state, witness))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chain_core::state::tendermint::BlockHeight;
    use chain_core::state::ChainState;
    use chain_core::tx::data::Tx;
    use chain_core::tx::witness::TxWitness;
    use chain_core::tx::{TxEnclaveAux, TxObfuscated};
    use client_common::tendermint::lite;
    use client_common::tendermint::types::*;
    use client_common::PrivateKey;

    fn transfer_transaction() -> TxEnclaveAux {
        TxEnclaveAux::TransferTx {
            inputs: Vec::new(),
            no_of_outputs: 2,
            payload: TxObfuscated {
                txid: [0; 32],
                key_from: BlockHeight::genesis(),
                init_vector: [0; 12],
                txpayload: Vec::new(),
            },
        }
    }

    #[derive(Clone)]
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

        fn block_batch<'a, T: Iterator<Item = &'a u64>>(&self, _heights: T) -> Result<Vec<Block>> {
            unreachable!()
        }

        fn block_results(&self, _height: u64) -> Result<BlockResults> {
            unreachable!()
        }

        fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> Result<Vec<BlockResults>> {
            unreachable!()
        }

        fn block_batch_verified<'a, T: Clone + Iterator<Item = &'a u64>>(
            &self,
            _state: lite::TrustedState,
            _heights: T,
        ) -> Result<(Vec<Block>, lite::TrustedState)> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<BroadcastTxResponse> {
            unreachable!()
        }

        fn query(&self, path: &str, _data: &[u8]) -> Result<AbciQuery> {
            match path {
                "mockdecrypt" => {
                    let response = DecryptionResponse {
                        txs: vec![TxWithOutputs::Transfer(Tx::new())],
                    }
                    .encode();

                    Ok(AbciQuery {
                        value: Some(response),
                        ..Default::default()
                    })
                }
                "mockencrypt" => {
                    let response = EncryptionResponse {
                        resp: Ok(transfer_transaction()),
                    }
                    .encode();

                    Ok(AbciQuery {
                        value: Some(response),
                        ..Default::default()
                    })
                }
                _ => Err(ErrorKind::InvalidInput.into()),
            }
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
                assert_eq!(2, no_of_outputs)
            }
            _ => unreachable!(),
        }
    }
}
