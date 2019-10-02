#![allow(missing_docs)]
use base64::decode;
use chrono::offset::Utc;
use chrono::DateTime;
use parity_scale_codec::Decode;
use serde::Deserialize;

use chain_core::tx::TxAux;

use crate::{ErrorKind, Result, ResultExt, Transaction};

#[derive(Debug, Deserialize)]
pub struct Block {
    pub block: BlockInner,
}

#[derive(Debug, Deserialize)]
pub struct BlockInner {
    pub header: Header,
    pub data: Data,
}

#[derive(Debug, Deserialize)]
pub struct Data {
    pub txs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct Header {
    pub app_hash: String,
    pub height: String,
    pub time: DateTime<Utc>,
}

impl Block {
    /// Returns un-encrypted transactions in a block (this may also contain invalid transactions)
    ///
    /// NOTE: Un-encrypted transactions only contain deposit stake and unbond stake transactions
    pub fn unencrypted_transactions(&self) -> Result<Vec<Transaction>> {
        match &self.block.data.txs {
            None => Ok(Vec::new()),
            Some(transactions) => transactions
                .iter()
                .map(|raw_transaction| -> Result<TxAux> {
                    let decoded = decode(&raw_transaction).chain(|| {
                        (
                            ErrorKind::DeserializationError,
                            "Unable to decode raw base64 bytes of transactions from block",
                        )
                    })?;
                    TxAux::decode(&mut decoded.as_slice()).chain(|| {
                        (
                            ErrorKind::DeserializationError,
                            "Unable to decode transactions from bytes in a block",
                        )
                    })
                })
                .filter_map(|tx_aux_result| match tx_aux_result {
                    Err(e) => Some(Err(e)),
                    Ok(tx_aux) => match tx_aux {
                        TxAux::DepositStakeTx { tx, .. } => {
                            Some(Ok(Transaction::DepositStakeTransaction(tx)))
                        }
                        TxAux::UnbondStakeTx(tx, _) => {
                            Some(Ok(Transaction::UnbondStakeTransaction(tx)))
                        }
                        _ => None,
                    },
                })
                .collect::<Result<Vec<Transaction>>>(),
        }
    }

    /// Returns height of this block
    pub fn height(&self) -> Result<u64> {
        self.block.header.height.parse::<u64>().chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to convert block height into integer",
            )
        })
    }

    /// Returns time of this block
    #[inline]
    pub fn time(&self) -> DateTime<Utc> {
        self.block.header.time
    }

    /// Returns app hash of this block
    #[inline]
    pub fn app_hash(&self) -> String {
        self.block.header.app_hash.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    use base64::encode;
    use parity_scale_codec::Encode;
    use secp256k1::recovery::{RecoverableSignature, RecoveryId};

    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::state::account::{
        StakedStateAddress, StakedStateOpAttributes, StakedStateOpWitness, UnbondTx,
    };
    use chain_core::tx::TxObfuscated;

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

    fn transfer_transaction() -> TxAux {
        TxAux::TransferTx {
            inputs: Vec::new(),
            no_of_outputs: 0,
            payload: TxObfuscated {
                txid: [0; 32],
                key_from: 0,
                init_vector: [0; 12],
                txpayload: Vec::new(),
            },
        }
    }

    #[test]
    fn check_unencrypted_transactions() {
        let transaction = unbond_transaction();
        let transfer_transaction = transfer_transaction();

        let block = Block {
            block: BlockInner {
                header: Header {
                    app_hash: "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C"
                        .to_owned(),
                    height: "1".to_owned(),
                    time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                },
                data: Data {
                    txs: Some(vec![
                        encode(&transaction.encode()),
                        encode(&transfer_transaction.encode()),
                    ]),
                },
            },
        };

        let unencrypted_transactions = block.unencrypted_transactions().unwrap();
        assert_eq!(1, unencrypted_transactions.len());

        match (transaction, &unencrypted_transactions[0]) {
            (
                TxAux::UnbondStakeTx(ref unbond_transaction, _),
                Transaction::UnbondStakeTransaction(ref unencrypted_unbond_transaction),
            ) => assert_eq!(unencrypted_unbond_transaction, unbond_transaction),
            _ => unreachable!(),
        }
    }

    #[test]
    fn check_height() {
        let block = Block {
            block: BlockInner {
                header: Header {
                    app_hash: "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C"
                        .to_owned(),
                    height: "1".to_owned(),
                    time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                },
                data: Data { txs: None },
            },
        };

        assert_eq!(1, block.height().unwrap());
    }

    #[test]
    fn check_wrong_height() {
        let block = Block {
            block: BlockInner {
                header: Header {
                    app_hash: "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C"
                        .to_owned(),
                    height: "a".to_owned(),
                    time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                },
                data: Data { txs: None },
            },
        };

        assert!(block.height().is_err());
    }
}
