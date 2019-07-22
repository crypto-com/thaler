use parity_codec::{Decode, Encode};

use chain_core::tx::data::{txid_hash, TxId};
use chain_core::tx::TxWithOutputs;
use client_common::tendermint::Client;
use client_common::{Error, ErrorKind, PrivateKey, Result, Transaction};
use enclave_protocol::{DecryptionRequest, DecryptionRequestBody, DecryptionResponse};

use crate::TransactionCipher;

/// Implementation of transaction cipher which uses Tendermint ABCI to encrypt/decrypt transactions
pub struct AbciTransactionCipher<C>
where
    C: Client,
{
    client: C,
}

impl<C> AbciTransactionCipher<C>
where
    C: Client,
{
    /// Creates a new instance of `AbciTransactionCipher`
    #[inline]
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

impl<C> TransactionCipher for AbciTransactionCipher<C>
where
    C: Client,
{
    fn decrypt(
        &self,
        transaction_ids: &[TxId],
        private_key: &PrivateKey,
    ) -> Result<Vec<Transaction>> {
        let body = DecryptionRequestBody {
            txs: transaction_ids.to_owned(),
        };

        let message = txid_hash(&body.encode());
        let signature = private_key.sign(message)?.serialize_compact().1;

        let request = DecryptionRequest {
            body,
            view_key_sig: signature,
        };

        let response = self
            .client
            .query("mockdecrypt", &request.encode())?
            .bytes()?;

        let txs = DecryptionResponse::decode(&mut response.as_slice())
            .ok_or_else(|| Error::from(ErrorKind::DeserializationError))?
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::encode;

    use chain_core::tx::data::Tx;
    use client_common::tendermint::types::*;

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

        fn block_results(&self, _height: u64) -> Result<BlockResults> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<()> {
            unreachable!()
        }

        fn query(&self, _path: &str, _data: &[u8]) -> Result<QueryResult> {
            let response = DecryptionResponse {
                txs: vec![TxWithOutputs::Transfer(Tx::new())],
            }
            .encode();

            Ok(QueryResult {
                response: Response {
                    value: encode(&response),
                },
            })
        }
    }

    #[test]
    fn check_decryption() {
        let cipher = AbciTransactionCipher::new(MockClient);

        assert_eq!(
            1,
            cipher
                .decrypt(&[[0; 32]], &PrivateKey::new().unwrap())
                .unwrap()
                .len()
        )
    }
}
