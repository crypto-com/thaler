use crate::app::app_init::{get_validator_key, ChainNodeApp, ChainNodeState};
use crate::enclave_bridge::EnclaveProxy;
use abci::{Event, KVPair, RequestEndBlock, ResponseEndBlock, ValidatorUpdate};
use chain_core::common::TendermintEventType;
use chain_core::state::account::{CouncilNode, StakedStateAddress};
use chain_core::state::tendermint::{TendermintValidatorAddress, TendermintVotePower};
use chain_tx_filter::BlockFilter;
use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use protobuf::RepeatedField;
use std::collections::BTreeMap;

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
        if !self.power_changed_in_block.is_empty() {
            let last_state = self
                .last_state
                .as_mut()
                .expect("Last app state not found, init chain was not called");
            let validators = get_validator_updates(
                last_state,
                &mut self.validator_voting_power,
                &self.power_changed_in_block,
                &self.new_nodes_in_block,
            );
            resp.set_validator_updates(RepeatedField::from(validators));
            self.power_changed_in_block.clear();
            self.new_nodes_in_block.clear();
        }
        self.last_state.as_mut().map(|mut x| x.last_block_height = _req.height)
            .expect("executing end block, but no app state stored (i.e. no initchain or recovery was executed)");
        resp
    }
}

fn get_validator_updates(
    last_state: &mut ChainNodeState,
    validator_voting_power: &mut BTreeMap<StakedStateAddress, TendermintVotePower>,
    power_changed_in_block: &BTreeMap<StakedStateAddress, TendermintVotePower>,
    new_nodes_in_block: &BTreeMap<StakedStateAddress, CouncilNode>,
) -> Vec<ValidatorUpdate> {
    // TODO: this shouldn't happen very often (depends mainly on the reward distribution frequency)
    // but it could perhaps be optimized
    let mut validators = Vec::with_capacity(power_changed_in_block.len());
    // step 1: update the index by power
    for (address, new_power) in power_changed_in_block.iter() {
        let old_power = validator_voting_power
            .get(&address)
            .copied()
            .unwrap_or_else(TendermintVotePower::zero);
        // sanity check, as multiple transactions/events may have cancelled out the vote power change
        if old_power != *new_power {
            let old_key = (old_power, *address);
            let node = last_state
                .validators
                .council_nodes_by_power
                .remove(&old_key)
                .unwrap_or_else(|| new_nodes_in_block[&address].clone());

            last_state
                .validators
                .council_nodes_by_power
                .insert((*new_power, *address), node);
        }
    }

    // for step 3
    let mut remaining_validators = validator_voting_power.clone();

    let mut new_to_track = Vec::new();
    let zero = TendermintVotePower::zero();
    // step 2: calculate updates for validators that are going to be in the validator set
    for ((voting_power, address), node) in last_state
        .validators
        .council_nodes_by_power
        .iter()
        .rev()
        .take(last_state.network_params.get_max_validators())
    {
        let old_power = validator_voting_power.get(&address);
        let create_update = match old_power {
            Some(p) if *p == *voting_power => {
                // no update
                remaining_validators.remove(address);
                false
            }
            Some(p) if *p != *voting_power && *voting_power > zero => {
                remaining_validators.remove(address);
                true
            }
            Some(_) => {
                // update in step 3
                remaining_validators.insert(*address, *voting_power);
                false
            }
            None => {
                // only updates for nodes with some voting power (not punished and bonded amount >= minimal)
                *voting_power > zero
            }
        };

        if create_update {
            let mut validator = ValidatorUpdate::default();
            validator.set_power(i64::from(*voting_power));
            validator.set_pub_key(get_validator_key(&node));
            validators.push(validator);
            validator_voting_power.insert(*address, *voting_power);
            let validator_address: TendermintValidatorAddress =
                node.consensus_pubkey.clone().into();
            if !last_state
                .validators
                .punishment
                .validator_liveness
                .contains_key(&validator_address)
            {
                new_to_track.push((validator_address, *address));
            }
        }
    }
    let window = last_state.network_params.get_block_signing_window();
    while let Some((validator_address, staking_address)) = new_to_track.pop() {
        last_state.validators.add_validator_for_tracking(
            validator_address,
            staking_address,
            window,
        );
    }
    // step 3: calculate updates for validators that were removed from the validator set
    for (address, voting_power) in remaining_validators.iter() {
        let key = (*voting_power, *address);
        let alt_key = (zero, *address);
        let node = &last_state
            .validators
            .council_nodes_by_power
            .get(&key)
            .unwrap_or_else(|| &last_state.validators.council_nodes_by_power[&alt_key]);
        let mut validator = ValidatorUpdate::default();
        // even if voting_power > 0 (bonded amount >= minimal and not jailed),
        // it may have been < lowest stake/voting power
        // if the the number of current validators == max validators,
        // hence it's set to 0 in this update to be removed
        validator.set_power(0);
        validator.set_pub_key(get_validator_key(&node));
        validators.push(validator);
        validator_voting_power.remove(address);

        let validator_address: TendermintValidatorAddress = node.consensus_pubkey.clone().into();
        last_state
            .validators
            .remove_validator_from_tracking(&validator_address);

        // FIXME: if voting_power == 0, schedule removal from tendermint_validator_addresses +
        // council_nodes_by_power after unbonding period
    }

    validators
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::app_init::ValidatorState;
    use crate::punishment::ValidatorPunishment;
    use crate::storage::tx::StarlingFixedKey;
    use chain_core::common::H256;
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::init::params::InitNetworkParameters;
    use chain_core::init::params::{
        JailingParameters, NetworkParameters, SlashRatio, SlashingParameters,
    };
    use chain_core::state::tendermint::TendermintValidatorPubKey;
    use chain_core::state::RewardsPoolState;
    use chain_core::tx::fee::{LinearFee, Milli};
    use std::str::FromStr;

    fn get_initial_state() -> (
        ChainNodeState,
        BTreeMap<StakedStateAddress, TendermintVotePower>,
        StakedStateAddress,
        TendermintValidatorPubKey,
        CouncilNode,
    ) {
        let genesis_app_hash = H256::default();
        let genesis_time = 0;
        let new_account_root = StarlingFixedKey::default();
        let rewards_pool = RewardsPoolState::new(Coin::one(), 0);
        let network_params = NetworkParameters::Genesis(InitNetworkParameters {
            initial_fee_policy: LinearFee::new(Milli::new(0, 0), Milli::new(0, 0)),
            required_council_node_stake: Coin::one(),
            unbonding_period: 1,
            jailing_config: JailingParameters {
                jail_duration: 60,
                block_signing_window: 5,
                missed_block_threshold: 1,
            },
            slashing_config: SlashingParameters {
                liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
                byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
                slash_wait_period: 30,
            },
            max_validators: 2,
        });
        let v1_address: StakedStateAddress =
            StakedStateAddress::from(RedeemAddress::from([0u8; 20]));
        let v1_key = TendermintValidatorPubKey::Ed25519([0u8; 32]);
        let v1_node = CouncilNode::new(v1_key.clone());
        let v1_power = TendermintVotePower::from(Coin::one());
        let mut validator_by_voting_power = BTreeMap::new();
        validator_by_voting_power.insert((v1_power, v1_address), v1_node.clone());
        let mut validator_voting_power = BTreeMap::new();
        validator_voting_power.insert(v1_address, v1_power);

        let tendermint_validator_addresses = BTreeMap::new();
        let validator_liveness = BTreeMap::new();
        let mut validator_state = ValidatorState {
            council_nodes_by_power: validator_by_voting_power,
            tendermint_validator_addresses,
            punishment: ValidatorPunishment {
                validator_liveness,
                slashing_schedule: Default::default(),
            },
        };
        validator_state.add_validator_for_tracking(v1_key.clone().into(), v1_address, 10);
        (
            ChainNodeState::genesis(
                genesis_app_hash,
                genesis_time,
                new_account_root,
                rewards_pool,
                network_params,
                validator_state,
            ),
            validator_voting_power,
            v1_address,
            v1_key,
            v1_node,
        )
    }

    fn add_node(
        address: [u8; 20],
        key: [u8; 32],
        power: Coin,
        last_state: &ChainNodeState,
        validator_voting_power: &BTreeMap<StakedStateAddress, TendermintVotePower>,
        power_changed_in_block: &mut BTreeMap<StakedStateAddress, TendermintVotePower>,
        new_nodes_in_block: &mut BTreeMap<StakedStateAddress, CouncilNode>,
    ) -> (CouncilNode, StakedStateAddress, TendermintValidatorAddress) {
        let v2_address: StakedStateAddress = StakedStateAddress::from(RedeemAddress::from(address));
        assert!(!validator_voting_power.contains_key(&v2_address));
        let v2_key = TendermintValidatorPubKey::Ed25519(key);
        let v2_keyaddress = TendermintValidatorAddress::from(&v2_key);
        assert!(!last_state
            .validators
            .punishment
            .validator_liveness
            .contains_key(&v2_keyaddress));
        assert!(!last_state
            .validators
            .tendermint_validator_addresses
            .contains_key(&v2_keyaddress));
        let v2_node = CouncilNode::new(v2_key);
        let v2_power = TendermintVotePower::from(power);
        power_changed_in_block.insert(v2_address, v2_power);
        new_nodes_in_block.insert(v2_address, v2_node.clone());
        (v2_node, v2_address, v2_keyaddress)
    }

    fn contain_address(
        address: &StakedStateAddress,
        keyaddress: &TendermintValidatorAddress,
        validator_voting_power: &BTreeMap<StakedStateAddress, TendermintVotePower>,
        last_state: &ChainNodeState,
    ) {
        assert!(validator_voting_power.contains_key(address));
        assert!(last_state
            .validators
            .punishment
            .validator_liveness
            .contains_key(keyaddress));
        assert!(last_state
            .validators
            .tendermint_validator_addresses
            .contains_key(keyaddress));
    }

    fn not_contain_address(
        address: &StakedStateAddress,
        keyaddress: &TendermintValidatorAddress,
        validator_voting_power: &BTreeMap<StakedStateAddress, TendermintVotePower>,
        last_state: &ChainNodeState,
    ) {
        assert!(!validator_voting_power.contains_key(address));
        assert!(!last_state
            .validators
            .punishment
            .validator_liveness
            .contains_key(keyaddress));
    }

    #[test]
    fn new_nodes_should_be_added() {
        let (mut last_state, mut validator_voting_power, _, _, _) = get_initial_state();
        let mut power_changed_in_block = BTreeMap::new();
        let mut new_nodes_in_block = BTreeMap::new();
        let (v2_node, v2_address, v2_keyaddress) = add_node(
            [1u8; 20],
            [1u8; 32],
            Coin::one(),
            &last_state,
            &validator_voting_power,
            &mut power_changed_in_block,
            &mut new_nodes_in_block,
        );

        let updates = get_validator_updates(
            &mut last_state,
            &mut validator_voting_power,
            &power_changed_in_block,
            &new_nodes_in_block,
        );
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].get_power(), 1);
        assert_eq!(*updates[0].get_pub_key(), get_validator_key(&v2_node));
        contain_address(
            &v2_address,
            &v2_keyaddress,
            &validator_voting_power,
            &last_state,
        );
    }

    #[test]
    fn nodes_with_lower_power_should_be_removed() {
        let (mut last_state, mut validator_voting_power, v1_address, v1_key, v1_node) =
            get_initial_state();
        let mut power_changed_in_block = BTreeMap::new();
        let mut new_nodes_in_block = BTreeMap::new();
        let two = (Coin::one() + Coin::one()).unwrap();
        let (v2_node, v2_address, v2_keyaddress) = add_node(
            [1u8; 20],
            [1u8; 32],
            two,
            &last_state,
            &validator_voting_power,
            &mut power_changed_in_block,
            &mut new_nodes_in_block,
        );
        let (v3_node, v3_address, v3_keyaddress) = add_node(
            [2u8; 20],
            [2u8; 32],
            two,
            &last_state,
            &validator_voting_power,
            &mut power_changed_in_block,
            &mut new_nodes_in_block,
        );

        let updates = get_validator_updates(
            &mut last_state,
            &mut validator_voting_power,
            &power_changed_in_block,
            &new_nodes_in_block,
        );
        assert_eq!(updates.len(), 3);
        for update in updates.iter() {
            let pk = update.get_pub_key().clone();
            match update.get_power() {
                0 => {
                    assert_eq!(pk, get_validator_key(&v1_node));
                }
                2 => {
                    assert!(pk == get_validator_key(&v2_node) || pk == get_validator_key(&v3_node))
                }
                _ => panic!("unexpected voting power"),
            }
        }
        not_contain_address(
            &v1_address,
            &TendermintValidatorAddress::from(&v1_key),
            &validator_voting_power,
            &last_state,
        );
        contain_address(
            &v2_address,
            &v2_keyaddress,
            &validator_voting_power,
            &last_state,
        );
        contain_address(
            &v3_address,
            &v3_keyaddress,
            &validator_voting_power,
            &last_state,
        );
    }

    #[test]
    fn nodes_with_0_power_should_be_removed() {
        let (mut last_state, mut validator_voting_power, v1_address, v1_key, v1_node) =
            get_initial_state();
        let mut power_changed_in_block = BTreeMap::new();
        let mut new_nodes_in_block = BTreeMap::new();
        let (v2_node, v2_address, v2_keyaddress) = add_node(
            [1u8; 20],
            [1u8; 32],
            Coin::one(),
            &last_state,
            &validator_voting_power,
            &mut power_changed_in_block,
            &mut new_nodes_in_block,
        );
        power_changed_in_block.insert(v1_address, TendermintVotePower::zero());

        let updates = get_validator_updates(
            &mut last_state,
            &mut validator_voting_power,
            &power_changed_in_block,
            &new_nodes_in_block,
        );

        assert_eq!(updates.len(), 2);
        for update in updates.iter() {
            let pk = update.get_pub_key().clone();
            match update.get_power() {
                0 => {
                    assert_eq!(pk, get_validator_key(&v1_node));
                }
                1 => {
                    assert_eq!(pk, get_validator_key(&v2_node));
                }
                _ => panic!("unexpected voting power"),
            }
        }
        not_contain_address(
            &v1_address,
            &TendermintValidatorAddress::from(&v1_key),
            &validator_voting_power,
            &last_state,
        );
        contain_address(
            &v2_address,
            &v2_keyaddress,
            &validator_voting_power,
            &last_state,
        );
    }
}
