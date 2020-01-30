#![allow(missing_docs)]
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::str::{from_utf8, FromStr};

use base64;
use serde::Deserialize;

use chain_core::common::{TendermintEventKey, TendermintEventType};
use chain_core::init::address::RedeemAddress;
use chain_core::init::{coin::Coin, MAX_COIN_DECIMALS};
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_tx_filter::BlockFilter;

use crate::tendermint::types::Height;
use crate::{Error, ErrorKind, Result, ResultExt};

#[derive(Debug, Deserialize)]
pub struct BlockResults {
    pub height: Height,
    pub results: Results,
}

#[derive(Debug, Deserialize)]
pub struct Results {
    pub deliver_tx: Option<Vec<DeliverTx>>,
    pub end_block: Option<EndBlock>,
}

#[derive(Debug, Deserialize)]
pub struct EndBlock {
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
pub struct DeliverTx {
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub event_type: String,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Attribute {
    pub key: String,
    pub value: String,
}

impl BlockResults {
    /// Returns transaction ids and the corresponding fees in block results
    pub fn fees(&self) -> Result<BTreeMap<TxId, Fee>> {
        match &self.results.deliver_tx {
            None => Ok(BTreeMap::default()),
            Some(deliver_tx) => {
                let mut fees: BTreeMap<TxId, Fee> = BTreeMap::new();

                for transaction in deliver_tx.iter() {
                    for event in transaction.events.iter() {
                        if event.event_type == TendermintEventType::ValidTransactions.to_string() {
                            let tx_id = find_tx_id_from_event_attributes(&event.attributes)?;
                            let fee = find_fee_from_event_attributes(&event.attributes)?;
                            if let (Some(tx_id), Some(fee)) = (tx_id, fee) {
                                fees.insert(tx_id, fee);
                            }
                        }
                    }
                }

                Ok(fees)
            }
        }
    }

    /// Checks if a StakedStateAddress is included in devlier_tx account event.
    /// Returns true when the address presents
    pub fn contains_account(&self, target_account: &StakedStateAddress) -> Result<bool> {
        match &self.results.deliver_tx {
            None => Ok(false),
            Some(deliver_tx) => {
                for transaction in deliver_tx.iter() {
                    for event in transaction.events.iter() {
                        if event.event_type != TendermintEventType::ValidTransactions.to_string() {
                            continue;
                        }
                        match find_account_from_event_attributes(&event.attributes)? {
                            None => continue,
                            Some(address) => {
                                if address == *target_account {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                }

                Ok(false)
            }
        }
    }

    /// Returns block filter in block results
    pub fn block_filter(&self) -> Result<BlockFilter> {
        match &self.results.end_block {
            None => Ok(BlockFilter::default()),
            Some(ref end_block) => {
                for event in end_block.events.iter() {
                    if event.event_type == TendermintEventType::BlockFilter.to_string() {
                        let attribute = &event.attributes[0];
                        let decoded = base64::decode(&attribute.value).chain(|| {
                            (
                                ErrorKind::DeserializationError,
                                "Unable to decode base64 bytes of block filter in block results",
                            )
                        })?;

                        return Ok(BlockFilter::try_from(decoded.as_slice()).map_err(
                            |message| Error::new(ErrorKind::DeserializationError, message),
                        )?);
                    }
                }

                Ok(BlockFilter::default())
            }
        }
    }
}

fn find_event_attribute_by_key(
    attributes: &[Attribute],
    target_key: TendermintEventKey,
) -> Result<Option<&Attribute>> {
    for attribute in attributes.iter() {
        let key = base64::decode(&attribute.key).chain(|| {
            (
                ErrorKind::DeserializationError,
                "Unable to decode base64 bytes of attribute key in block results",
            )
        })?;
        if key == target_key {
            return Ok(Some(attribute));
        }
    }

    Ok(None)
}

fn find_fee_from_event_attributes(attributes: &[Attribute]) -> Result<Option<Fee>> {
    let maybe_attribute = find_event_attribute_by_key(attributes, TendermintEventKey::Fee)?;
    match maybe_attribute {
        None => Ok(None),
        Some(attribute) => {
            let raw_fee_text = base64::decode(&attribute.value).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to decode base64 bytes of fee in block results",
                )
            })?;
            let fee_text = from_utf8(&raw_fee_text)
                .chain(|| (ErrorKind::DeserializationError, "Invalid fee text encoding"))?;
            let mut parts = fee_text.split_terminator('.').map(|s| s.parse::<u64>());
            match (parts.next(), parts.next()) {
                (Some(Ok(a)), Some(Ok(b))) => {
                    let base_fee = Fee::new(
                        Coin::new(a * MAX_COIN_DECIMALS + b)
                            .chain(|| (ErrorKind::DeserializationError, "Invalid fee amount"))?,
                    );
                    Ok(Some(base_fee))
                }
                _ => Err(Error::new(
                    ErrorKind::DeserializationError,
                    "Invalid fee text",
                )),
            }
        }
    }
}

fn find_tx_id_from_event_attributes(attributes: &[Attribute]) -> Result<Option<[u8; 32]>> {
    let maybe_attribute = find_event_attribute_by_key(attributes, TendermintEventKey::TxId)?;
    match maybe_attribute {
        None => Ok(None),
        Some(attribute) => {
            let tx_id = base64::decode(&attribute.value).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to decode base64 bytes of transaction id in block results",
                )
            })?;
            let tx_id = hex::decode(&tx_id).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to decode hex bytes of transaction id in block results",
                )
            })?;
            if 32 != tx_id.len() {
                return Err(Error::new(
                    ErrorKind::DeserializationError,
                    "Expected transaction id of 32 bytes",
                ));
            }
            let mut id: [u8; 32] = [0; 32];
            id.copy_from_slice(&tx_id);

            Ok(Some(id))
        }
    }
}

fn find_account_from_event_attributes(
    attributes: &[Attribute],
) -> Result<Option<StakedStateAddress>> {
    let maybe_attribute = find_event_attribute_by_key(attributes, TendermintEventKey::Account)?;
    match maybe_attribute {
        None => Ok(None),
        Some(attribute) => {
            let account = base64::decode(&attribute.value).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to decode base64 bytes of account in block results",
                )
            })?;
            let address = String::from_utf8(account).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to decode string of account in block results",
                )
            })?;
            let redeem_address = RedeemAddress::from_str(&address).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to decode account address in block results",
                )
            })?;
            let address = StakedStateAddress::from(redeem_address);

            Ok(Some(address))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::encode;

    mod find_account_from_event_attributes {
        use super::*;

        #[test]
        fn should_return_err_when_event_value_is_invalid_base64_encoded() {
            let block_results = BlockResults {
                height: Height::default().increment(),
                results: Results {
                    deliver_tx: Some(vec![DeliverTx {
                        events: vec![Event {
                            event_type: TendermintEventType::ValidTransactions.to_string(),
                            attributes: vec![Attribute {
                                key: TendermintEventKey::Account.to_base64_string(),
                                value: "Invalid==".to_owned(),
                            }],
                        }],
                    }]),
                    end_block: None,
                },
            };

            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_err());
            assert_eq!(ErrorKind::DeserializationError, result.unwrap_err().kind());
        }

        #[test]
        fn should_return_err_when_account_value_is_invalid_utf8_string() {
            let block_results = BlockResults {
                height: Height::default().increment(),
                results: Results {
                    deliver_tx: Some(vec![DeliverTx {
                        events: vec![Event {
                            event_type: TendermintEventType::ValidTransactions.to_string(),
                            attributes: vec![Attribute {
                                key: TendermintEventKey::Account.to_base64_string(),
                                value: base64::encode(&vec![0, 159, 146, 150]),
                            }],
                        }],
                    }]),
                    end_block: None,
                },
            };

            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_err());
            assert_eq!(ErrorKind::DeserializationError, result.unwrap_err().kind());
        }

        #[test]
        fn should_return_err_when_account_address_is_invalid() {
            let block_results = BlockResults {
                height: Height::default().increment(),
                results: Results {
                    deliver_tx: Some(vec![DeliverTx {
                        events: vec![Event {
                            event_type: TendermintEventType::ValidTransactions.to_string(),
                            attributes: vec![Attribute {
                                key: TendermintEventKey::Account.to_base64_string(),
                                value: base64::encode("0xInvalid".as_bytes()),
                            }],
                        }],
                    }]),
                    end_block: None,
                },
            };

            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_err());
            assert_eq!(ErrorKind::DeserializationError, result.unwrap_err().kind());
        }

        #[test]
        fn should_return_ok_of_none_when_block_results_has_no_account_event() {
            let block_results = BlockResults {
                height: Height::default().increment(),
                results: Results {
                    deliver_tx: Some(vec![DeliverTx {
                        events: vec![Event {
                            event_type: TendermintEventType::ValidTransactions.to_string(),
                            attributes: vec![Attribute {
                                key: TendermintEventKey::TxId.to_base64_string(),
                                value: "MDc2NmQ0ZTFjMDkxMjRhZjlhZWI0YTdlZDk5ZDgxNjU0YTg0NDczZjEzMzk0OGNlYTA1MGRhYTE3ZmYwZTdmZg==".to_owned(),
                            }],
                        }],
                    }]),
                    end_block: None,
                },
            };

            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_ok());
            assert_eq!(false, result.unwrap());
        }

        #[test]
        fn should_return_ok_of_true_when_block_results_has_the_target_account_event() {
            let block_results = BlockResults {
                height: Height::default().increment(),
                results: Results {
                    deliver_tx: Some(vec![DeliverTx {
                        events: vec![Event {
                            event_type: TendermintEventType::ValidTransactions.to_string(),
                            attributes: vec![Attribute {
                                key: TendermintEventKey::Account.to_base64_string(),
                                value: base64::encode(
                                    "0xe4a2a719ca933d3f79a8506aa96cefde3405b0a7".as_bytes(),
                                ),
                            }],
                        }],
                    }]),
                    end_block: None,
                },
            };

            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0xe4a2a719ca933d3f79a8506aa96cefde3405b0a7").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_ok());
            assert_eq!(true, result.unwrap());
        }

        #[test]
        fn should_return_ok_of_true_when_target_account_event_is_from_second_transaction() {
            let block_results = BlockResults {
                height: Height::default().increment(),
                results: Results {
                    deliver_tx: Some(vec![
                        DeliverTx {
                            events: vec![Event {
                                event_type: TendermintEventType::ValidTransactions.to_string(),
                                attributes: vec![Attribute {
                                    key: TendermintEventKey::TxId.to_base64_string(),
                                    value: "MDc2NmQ0ZTFjMDkxMjRhZjlhZWI0YTdlZDk5ZDgxNjU0YTg0NDczZjEzMzk0OGNlYTA1MGRhYTE3ZmYwZTdmZg==".to_owned(),
                                }],
                            }],
                        },
                        DeliverTx {
                            events: vec![Event {
                                event_type: TendermintEventType::ValidTransactions.to_string(),
                                attributes: vec![Attribute {
                                    key: TendermintEventKey::Account.to_base64_string(),
                                    value: base64::encode(
                                        "0xe4a2a719ca933d3f79a8506aa96cefde3405b0a7".as_bytes(),
                                    ),
                                }],
                            }],
                        },
                    ]),
                    end_block: None,
                },
            };

            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0xe4a2a719ca933d3f79a8506aa96cefde3405b0a7").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_ok());
            assert_eq!(true, result.unwrap());
        }

        #[test]
        fn should_return_ok_of_true_when_account_event_exists_in_multiple_transactions() {
            let block_results = BlockResults {
                height: Height::default().increment(),
                results: Results {
                    deliver_tx: Some(vec![
                        DeliverTx {
                            events: vec![Event {
                                event_type: TendermintEventType::ValidTransactions.to_string(),
                                attributes: vec![Attribute {
                                    key: TendermintEventKey::Account.to_base64_string(),
                                    value: base64::encode(
                                        "0xa0b73e1ff0b80914ab6fe0444e65848c4c34450b".as_bytes(),
                                    ),
                                }],
                            }],
                        },
                        DeliverTx {
                            events: vec![Event {
                                event_type: TendermintEventType::ValidTransactions.to_string(),
                                attributes: vec![Attribute {
                                    key: TendermintEventKey::Account.to_base64_string(),
                                    value: base64::encode(
                                        "0xe4a2a719ca933d3f79a8506aa96cefde3405b0a7".as_bytes(),
                                    ),
                                }],
                            }],
                        },
                    ]),
                    end_block: None,
                },
            };

            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0xe4a2a719ca933d3f79a8506aa96cefde3405b0a7").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_ok());
            assert_eq!(true, result.unwrap());
        }
    }

    #[test]
    fn check_ids() {
        let block_results = BlockResults {
            height: Height::default().increment(),
            results: Results {
                deliver_tx: Some(vec![DeliverTx {
                    events: vec![Event {
                        event_type: TendermintEventType::ValidTransactions.to_string(),
                        attributes: vec![Attribute {
                            key: TendermintEventKey::TxId.to_base64_string(),
                            value: "MDc2NmQ0ZTFjMDkxMjRhZjlhZWI0YTdlZDk5ZDgxNjU0YTg0NDczZjEzMzk0OGNlYTA1MGRhYTE3ZmYwZTdmZg==".to_owned(),
                        },
                        Attribute {
                            key: TendermintEventKey::Fee.to_base64_string(),
                            value: "MC4wMDAwMDU3OA==".to_owned(),
                        }
                        ],
                    }],
                }]),
                end_block: None,
            },
        };
        assert_eq!(1, block_results.fees().unwrap().len());
    }

    #[test]
    fn check_block_filter() {
        let block_results = BlockResults {
            height: Height::default().increment(),
            results: Results {
                deliver_tx: None,
                end_block: Some(EndBlock {
                    events: vec![Event {
                        event_type: TendermintEventType::BlockFilter.to_string(),
                        attributes: vec![Attribute {
                            key: TendermintEventKey::EthBloom.to_base64_string(),
                            value: encode(&[0; 256][..]),
                        }],
                    }],
                }),
            },
        };
        assert!(block_results.block_filter().is_ok());
    }

    #[test]
    fn check_wrong_id() {
        let block_results = BlockResults {
            height: Height::default().increment(),
            results: Results {
                deliver_tx: Some(vec![DeliverTx {
                    events: vec![Event {
                        event_type: TendermintEventType::ValidTransactions.to_string(),
                        attributes: vec![Attribute {
                            key: TendermintEventKey::TxId.to_base64_string(),
                            value: "kOzcmhZgAAaw5riwRjjKNe+foJEiDAOObTDQ=".to_owned(),
                        }],
                    }],
                }]),
                end_block: None,
            },
        };

        assert!(block_results.fees().is_err());
    }

    #[test]
    fn check_null_deliver_tx() {
        let block_results = BlockResults {
            height: Height::default().increment(),
            results: Results {
                deliver_tx: None,
                end_block: None,
            },
        };
        assert_eq!(0, block_results.fees().unwrap().len());
    }

    mod find_event_attribute_by_key {
        use super::*;

        #[test]
        fn should_return_err_when_event_key_is_invalid_base64_encoded() {
            let attributes = vec![Attribute {
                key: "Invalid==".to_owned(),
                value: "MDc2NmQ0ZTFjMDkxMjRhZjlhZWI0YTdlZDk5ZDgxNjU0YTg0NDczZjEzMzk0OGNlYTA1MGRhYTE3ZmYwZTdmZg==".to_owned(),
            }];

            let result = find_event_attribute_by_key(&attributes, TendermintEventKey::Account);
            assert!(result.is_err());
            assert_eq!(ErrorKind::DeserializationError, result.unwrap_err().kind());
        }

        #[test]
        fn should_return_result_of_none_when_key_does_not_exist() {
            let attribute = Attribute {
                key: TendermintEventKey::TxId.to_base64_string(),
                value: "Y2MwMjkxNThhZTFmMjVlN2I5ZGVhZTc5MWVjMTQ2MDA5ZTNjZTliMjZhMjFmZDEzOTZiMTA3YzYyZDIzNmMwOQ==".to_owned(),
            };
            let attributes = vec![attribute];

            assert!(
                find_event_attribute_by_key(&attributes, TendermintEventKey::Account)
                    .unwrap()
                    .is_none()
            );
        }

        #[test]
        fn should_return_result_of_the_attribute_when_key_exist() {
            let account_attribute = Attribute {
                key: TendermintEventKey::Account.to_base64_string(),
                value: "MHhlNGEyYTcxOWNhOTMzZDNmNzlhODUwNmFhOTZjZWZkZTM0MDViMGE3".to_owned(),
            };
            let attributes = vec![account_attribute.clone()];

            assert_eq!(
                account_attribute,
                find_event_attribute_by_key(&attributes, TendermintEventKey::Account)
                    .unwrap()
                    .unwrap()
                    .to_owned()
            );
        }
    }
}
