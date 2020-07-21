use std::convert::TryInto;

use crate::app::app_init::ChainNodeApp;
use crate::enclave_bridge::EnclaveProxy;
use abci::{Event, Pair as KVPair, PubKey, RequestEndBlock, ResponseEndBlock, ValidatorUpdate};
use chain_core::common::TendermintEventType;
use chain_tx_filter::BlockFilter;
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponseOk};

impl<T: EnclaveProxy + 'static> ChainNodeApp<T> {
    /// tags the block with the transaction filter + computes validator set changes
    pub fn end_block_handler(&mut self, req: &RequestEndBlock) -> ResponseEndBlock {
        let mut resp = ResponseEndBlock::new();
        if !self.delivered_txs.is_empty() {
            let end_block_resp = self
                .tx_validator
                .process_request(IntraEnclaveRequest::EndBlock);
            if let Ok(IntraEnclaveResponseOk::EndBlock(maybe_filter)) = end_block_resp {
                if let Some(raw_filter) = maybe_filter {
                    let filter = BlockFilter::from(&*raw_filter);

                    let (key, value) = filter.get_tendermint_kv();
                    let mut kvpair = KVPair::new();
                    kvpair.key = key;
                    kvpair.value = value;
                    let mut event = Event::new();
                    event.field_type = TendermintEventType::BlockFilter.to_string();
                    event.attributes.push(kvpair);
                    resp.events.push(event);
                }
            } else {
                panic!("end block request to obtain the block filter failed");
            }
        }
        // TODO: skipchain-based validator changes?
        let state = self.last_state.as_mut().expect("executing end block, but no app state stored (i.e. no initchain or recovery was executed)");
        let val_updates = state.staking_table.end_block(
            &staking_getter!(self, state.staking_version),
            state.top_level.network_params.get_max_validators(),
        );

        resp.set_validator_updates(
            val_updates
                .into_iter()
                .map(|(pubkey, power)| {
                    let mut validator = ValidatorUpdate::default();
                    validator.set_power(power.into());

                    let mut pk = PubKey::new();
                    let (keytype, key) = pubkey.to_validator_update();
                    pk.set_field_type(keytype);
                    pk.set_data(key);
                    validator.set_pub_key(pk);

                    validator
                })
                .collect(),
        );
        state.last_block_height = req.height.try_into().unwrap();
        resp
    }
}
