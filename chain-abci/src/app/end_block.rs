use crate::app::app_init::ChainNodeApp;
use crate::enclave_bridge::EnclaveProxy;
use abci::{Event, KVPair, RequestEndBlock, ResponseEndBlock};
use chain_core::common::TendermintEventType;
use chain_tx_filter::BlockFilter;
use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use protobuf::RepeatedField;

impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// tags the block with the transaction filter + computes validator set changes
    pub fn end_block_handler(&mut self, _req: &RequestEndBlock) -> ResponseEndBlock {
        let mut resp = ResponseEndBlock::new();
        if !self.delivered_txs.is_empty() {
            let end_block_resp = self.tx_validator.process_request(EnclaveRequest::EndBlock);
            if let EnclaveResponse::EndBlock(Ok(maybe_filter)) = end_block_resp {
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
        self.last_state.as_mut().map(|mut state| {
        if let Some(validators) = state.validators.get_validator_updates(
            state.top_level.network_params.get_block_signing_window(),
            state.top_level.network_params.get_max_validators()) {
            resp.set_validator_updates(RepeatedField::from(validators));
        }
        state.last_block_height = _req.height;
        }).expect("executing end block, but no app state stored (i.e. no initchain or recovery was executed)");
        resp
    }
}
