use failure::ResultExt;
use parity_scale_codec::{Decode, Encode};

use chain_core::tx::data::{txid_hash, TxId};
use chain_core::tx::{TxAux, TxWithOutputs};
use client_common::tendermint::Client;
use client_common::{ErrorKind, PrivateKey, Result, SignedTransaction, Transaction};
use enclave_protocol::{
    DecryptionRequest, DecryptionRequestBody, DecryptionResponse, EncryptionRequest,
    EncryptionResponse,
};

use crate::TransactionCipher;

/// Implementation of transaction cipher which uses Tendermint ABCI to encrypt/decrypt transactions
#[derive(Debug, Clone)]
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

    fn encrypt_request(&self, encryption_request: EncryptionRequest) -> Result<TxAux> {
        let response = self
            .client
            .query("mockencrypt", &encryption_request.encode())?
            .bytes()?;

        let encrypted_transaction = EncryptionResponse::decode(&mut response.as_slice())
            .context(ErrorKind::DeserializationError)?
            .tx;

        Ok(encrypted_transaction)
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
            .context(ErrorKind::DeserializationError)?
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
            SignedTransaction::UnbondStakeTransaction(tx, witness) => {
                Ok(TxAux::UnbondStakeTx(tx, witness))
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

    use base64::encode;

    use chain_core::tx::data::Tx;
    use chain_core::tx::witness::TxWitness;
    use chain_core::tx::TxObfuscated;
    use client_common::tendermint::types::*;

    fn transfer_transaction() -> TxAux {
        TxAux::TransferTx {
            txid: [0; 32],
            inputs: Vec::new(),
            no_of_outputs: 2,
            payload: TxObfuscated {
                key_from: 0,
                nonce: [0; 12],
                txpayload: Vec::new(),
            },
        }
    }

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

        fn query(&self, path: &str, _data: &[u8]) -> Result<QueryResult> {
            match path {
                "mockdecrypt" => {
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
                "mockencrypt" => {
                    let response = EncryptionResponse {
                        tx: transfer_transaction(),
                    }
                    .encode();

                    Ok(QueryResult {
                        response: Response {
                            value: encode(&response),
                        },
                    })
                }
                _ => Err(ErrorKind::InvalidInput.into()),
            }
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

    #[test]
    fn check_encryption() {
        let cipher = AbciTransactionCipher::new(MockClient);

        let encrypted_transaction = cipher
            .encrypt(SignedTransaction::TransferTransaction(
                Tx::default(),
                TxWitness::default(),
            ))
            .unwrap();

        match encrypted_transaction {
            TxAux::TransferTx { no_of_outputs, .. } => assert_eq!(2, no_of_outputs),
            _ => unreachable!(),
        }
    }
}
