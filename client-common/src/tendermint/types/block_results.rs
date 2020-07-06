#![allow(missing_docs)]
use indexmap::IndexMap;
use std::convert::TryFrom;
use std::str::{from_utf8, FromStr};

use chain_core::common::{TendermintEventKey, TendermintEventType};
use chain_core::init::{coin::Coin, MAX_COIN_DECIMALS};
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_tx_filter::BlockFilter;

use crate::tendermint::types::BlockResultsResponse;
use crate::{Error, ErrorKind, Result, ResultExt};
use tendermint::abci::tag::Tag as Attribute;

pub trait BlockResults {
    /// Returns transaction ids and the corresponding fees in block results
    fn fees(&self) -> Result<IndexMap<TxId, Fee>>;

    /// Checks if a StakedStateAddress is included in devlier_tx account event.
    /// Returns true when the address presents
    fn contains_account(&self, target_account: &StakedStateAddress) -> Result<bool>;

    /// Checks if the block contains a staking stransaction
    /// Returns true when contains a staking transaction
    fn contains_staking(&self) -> bool;

    /// Returns block filter in block results
    fn block_filter(&self) -> Result<BlockFilter>;
}

impl BlockResults for BlockResultsResponse {
    fn fees(&self) -> Result<IndexMap<TxId, Fee>> {
        match &self.txs_results {
            None => Ok(IndexMap::default()),
            Some(deliver_txs) => {
                let mut fees: IndexMap<TxId, Fee> = IndexMap::new();
                for deliver_txs in deliver_txs.iter() {
                    for event in deliver_txs.events.iter() {
                        if event.type_str == TendermintEventType::ValidTransactions.to_string() {
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

    fn contains_staking(&self) -> bool {
        if let Some(deliver_tx) = &self.txs_results {
            for deliver_tx in deliver_tx.iter() {
                if deliver_tx
                    .events
                    .iter()
                    .map(|e| &e.type_str)
                    .any(|x| x == &TendermintEventType::StakingChange.to_string())
                {
                    return true;
                }
            }
        }
        false
    }

    fn contains_account(&self, target_account: &StakedStateAddress) -> Result<bool> {
        match &self.txs_results {
            None => Ok(false),
            Some(deliver_tx) => {
                for deliver_tx in deliver_tx.iter() {
                    for event in deliver_tx.events.iter() {
                        if event.type_str != TendermintEventType::StakingChange.to_string() {
                            continue;
                        }
                        match find_staking_address_from_event_attributes(&event.attributes)? {
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

    fn block_filter(&self) -> Result<BlockFilter> {
        match &self.end_block_events {
            None => Ok(BlockFilter::default()),
            Some(events) => {
                for event in events.iter() {
                    if event.type_str == TendermintEventType::BlockFilter.to_string() {
                        let attribute = &event.attributes[0];
                        let decoded = base64::decode(attribute.value.as_ref()).chain(|| {
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
        let key = base64::decode(attribute.key.as_ref()).chain(|| {
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
            let raw_fee_text = base64::decode(attribute.value.as_ref()).chain(|| {
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
            let tx_id = base64::decode(attribute.value.as_ref()).chain(|| {
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

fn find_staking_address_from_event_attributes(
    attributes: &[Attribute],
) -> Result<Option<StakedStateAddress>> {
    let maybe_attribute =
        find_event_attribute_by_key(attributes, TendermintEventKey::StakingAddress)?;
    match maybe_attribute {
        None => Ok(None),
        Some(attribute) => {
            let staking_address = base64::decode(&attribute.value.as_ref()).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to decode base64 bytes of account in block results",
                )
            })?;
            let staking_address = String::from_utf8(staking_address).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to decode string of account in block results",
                )
            })?;
            let staking_address = StakedStateAddress::from_str(&staking_address).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to decode account address in block results",
                )
            })?;

            Ok(Some(staking_address))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_core::init::address::RedeemAddress;
    use tendermint::abci::tag::{Key, Value};

    mod block_results_contains_account {
        use super::*;

        #[test]
        fn should_return_err_when_staking_address_value_is_invalid_utf8_string() {
            let response_str = r#"{"height": "37", "txs_results": [{"code": 0, "data": null, "log": "", "info": "", "gasWanted": "0", "gasUsed": "0", "events": [{"type": "staking_change", "attributes": [{"key": "c3Rha2luZ19hZGRyZXNz", "value": "AJ+Slg=="}]}], "codespace": ""}], "begin_block_events": null, "end_block_events": [{"type": "block_filter", "attributes": [{"key": "ZXRoYmxvb20=", "value": "AAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}]}], "validator_updates": null, "consensus_param_updates": null}"#;
            let block_results: BlockResultsResponse =
                serde_json::from_str(&response_str).expect("invalid response str");
            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_err());
            assert_eq!(ErrorKind::DeserializationError, result.unwrap_err().kind());
        }

        #[test]
        fn should_return_err_when_staking_address_is_invalid() {
            let response_str = r#"{"height": "37", "txs_results": [{"code": 0, "data": null, "log": "", "info": "", "gasWanted": "0", "gasUsed": "0", "events": [{"type": "staking_change", "attributes": [{"key": "c3Rha2luZ19hZGRyZXNz", "value": "invalidbase64string"}]}], "codespace": ""}], "begin_block_events": null, "end_block_events": [{"type": "block_filter", "attributes": [{"key": "ZXRoYmxvb20=", "value": "AAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}]}], "validator_updates": null, "consensus_param_updates": null}"#;
            let block_results: BlockResultsResponse = serde_json::from_str(response_str).unwrap();
            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_err());
            assert_eq!(ErrorKind::DeserializationError, result.unwrap_err().kind());
        }

        #[test]
        fn should_return_ok_of_none_when_block_results_has_no_staking_change_event() {
            let response_str = r#"{"height": "3", "txs_results": null, "begin_block_events": null, "end_block_events": null, "validator_updates": null, "consensus_param_updates": null}"#;
            let block_results: BlockResultsResponse =
                serde_json::from_str(response_str).expect("invalid response str");
            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0x0e7c045110b8dbf29765047380898919c5cb56f4").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_ok());
            assert_eq!(false, result.unwrap());
        }

        #[test]
        fn should_return_ok_of_true_when_block_results_has_the_target_account_event() {
            let response_str = r#"{"height": "37", "txs_results": [{"code": 0, "data": null, "log": "", "info": "", "gasWanted": "0", "gasUsed": "0", "events": [{"type": "staking_change", "attributes": [{"key": "c3Rha2luZ19hZGRyZXNz", "value": "MHgzMzUwMmVkMzlkMGM0ZTIwNDRmYjM3ZmRjZDUxNjE0OTNmNTkwMGMz"}]}], "codespace": ""}], "begin_block_events": null, "end_block_events": [{"type": "block_filter", "attributes": [{"key": "ZXRoYmxvb20=", "value": "AAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}]}], "validator_updates": null, "consensus_param_updates": null}"#;
            let block_results: BlockResultsResponse =
                serde_json::from_str(response_str).expect("invalid response str");
            let target_account = StakedStateAddress::from(
                RedeemAddress::from_str("0x33502ed39d0c4e2044fb37fdcd5161493f5900c3").unwrap(),
            );
            let result = block_results.contains_account(&target_account);
            assert!(result.is_ok());
            assert_eq!(true, result.unwrap());
        }
    }

    #[test]
    fn check_ids() {
        let response_str = r#"{"height": "38", "txs_results": [{"code": 0, "data": null, "log": "", "info": "", "gasWanted": "0", "gasUsed": "0", "events": [{"type": "valid_txs", "attributes": [{"key": "ZmVl", "value": "MC4wMDAwMDYzMg=="}, {"key": "dHhpZA==", "value": "MGNkMDc4MDI3NzBiOGMwYzBkNjgwYTFiYTU5ODg1OGZlZDFhZDQ4MDY1MTgzMDUyMjgxOWQ0MzBiNzVlYTBlMQ=="}]}], "codespace": ""}], "begin_block_events": null, "end_block_events": [{"type": "block_filter", "attributes": [{"key": "ZXRoYmxvb20=", "value": "AAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAA=="}]}], "validator_updates": null, "consensus_param_updates": null}"#;
        let block_results: BlockResultsResponse =
            serde_json::from_str(response_str).expect("invalid response str");
        assert_eq!(1, block_results.fees().unwrap().len());
    }

    #[test]
    fn check_block_filter() {
        let response_str = r#"{"height": "37", "txs_results": [{"code": 0, "data": null, "log": "", "info": "", "gasWanted": "0", "gasUsed": "0", "events": [{"type": "valid_txs", "attributes": [{"key": "ZmVl", "value": "MC4wMDAwMDMwNw=="}, {"key": "YWNjb3VudA==", "value": "MHgzMzUwMmVkMzlkMGM0ZTIwNDRmYjM3ZmRjZDUxNjE0OTNmNTkwMGMz"}, {"key": "dHhpZA==", "value": "ZjFmNzNkNmFjZWMyMTExOGRkMWUzNmY2ODRhYWUyMmM2Y2IxN2ZjNTFhZGEzNGEzNDIzMDlkNTMxY2I5YmU4ZA=="}]}], "codespace": ""}], "begin_block_events": null, "end_block_events": [{"type": "block_filter", "attributes": [{"key": "ZXRoYmxvb20=", "value": "AAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}]}], "validator_updates": null, "consensus_param_updates": null}"#;
        let block_results: BlockResultsResponse =
            serde_json::from_str(response_str).expect("invalid response str");
        assert!(block_results.block_filter().is_ok());
    }

    #[test]
    fn check_wrong_id() {
        let response_str = r#"{"height": "38", "txs_results": [{"code": 0, "data": null, "log": "", "info": "", "gasWanted": "0", "gasUsed": "0", "events": [{"type": "valid_txs", "attributes": [{"key": "dHhpZA==", "value": "kOzcmhZgAAaw5riwRjjKNe+foJEiDAOObTDQ="}]}], "codespace": ""}], "begin_block_events": null, "end_block_events": [{"type": "block_filter", "attributes": [{"key": "ZXRoYmxvb20=", "value": "AAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAA=="}]}], "validator_updates": null, "consensus_param_updates": null}"#;
        let block_results: BlockResultsResponse =
            serde_json::from_str(response_str).expect("invalid response str");
        assert!(block_results.fees().is_err());
    }

    #[test]
    fn check_null_deliver_tx() {
        let block_results = BlockResultsResponse {
            height: Default::default(),
            txs_results: None,
            begin_block_events: None,
            end_block_events: None,
            validator_updates: vec![],
            consensus_param_updates: None,
        };
        assert_eq!(0, block_results.fees().unwrap().len());
    }

    mod find_event_attribute_by_key {
        use super::*;

        #[test]
        fn should_return_err_when_event_key_is_invalid_base64_encoded() {
            let account_attribute = Attribute {
                key: Key::from_str("Invalid==").unwrap(),
                value: Value::from_str("MHhlNGEyYTcxOWNhOTMzZDNmNzlhODUwNmFhOTZjZWZkZTM0MDViMGE3")
                    .unwrap(),
            };
            let attributes = vec![account_attribute.clone()];

            let result =
                find_event_attribute_by_key(&attributes, TendermintEventKey::StakingAddress);
            assert!(result.is_err());
            assert_eq!(ErrorKind::DeserializationError, result.unwrap_err().kind());
        }

        #[test]
        fn should_return_result_of_none_when_key_does_not_exist() {
            let account_attribute = Attribute {
                key: Key::from_str(&TendermintEventKey::TxId.to_base64_string()).unwrap(),
                value: Value::from_str("MHhlNGEyYTcxOWNhOTMzZDNmNzlhODUwNmFhOTZjZWZkZTM0MDViMGE3")
                    .unwrap(),
            };
            let attributes = vec![account_attribute.clone()];

            assert!(
                find_event_attribute_by_key(&attributes, TendermintEventKey::StakingAddress)
                    .unwrap()
                    .is_none()
            );
        }

        #[test]
        fn should_return_result_of_the_attribute_when_key_exist() {
            let account_attribute = Attribute {
                key: Key::from_str(&TendermintEventKey::StakingAddress.to_base64_string()).unwrap(),
                value: Value::from_str("MHhlNGEyYTcxOWNhOTMzZDNmNzlhODUwNmFhOTZjZWZkZTM0MDViMGE3")
                    .unwrap(),
            };
            let attributes = vec![account_attribute.clone()];
            let attribute_finded =
                find_event_attribute_by_key(&attributes, TendermintEventKey::StakingAddress)
                    .unwrap()
                    .unwrap()
                    .to_owned();

            assert_eq!(
                account_attribute.key.as_ref(),
                attribute_finded.key.as_ref(),
            );
            assert_eq!(
                account_attribute.value.as_ref(),
                attribute_finded.value.as_ref(),
            );
        }
    }
}
