use crate::app::app_init::{get_validator_key, validator_state::ValidatorState};
use abci::ValidatorUpdate;
use chain_core::state::tendermint::{TendermintValidatorAddress, TendermintVotePower};

impl ValidatorState {
    pub fn get_validator_updates(
        &mut self,
        // validators_state: &mut ValidatorState,
        block_signing_window: u16,
        max_validators: usize,
        // validator_voting_power: &mut BTreeMap<StakedStateAddress, TendermintVotePower>,
        // power_changed_in_block: &BTreeMap<StakedStateAddress, TendermintVotePower>,
        // new_nodes_in_block: &BTreeMap<StakedStateAddress, CouncilNode>,
    ) -> Option<Vec<ValidatorUpdate>> {
        let changed_nodes_len = self.validator_state_helper.changed_nodes();
        if changed_nodes_len > 0 {
            // TODO: this shouldn't happen very often (depends mainly on the reward distribution frequency)
            // but it could perhaps be optimized
            let mut validators = Vec::with_capacity(self.validator_state_helper.changed_nodes());
            // step 1: update the index by power
            for (address, new_power) in self.validator_state_helper.changes() {
                let old_power = self
                    .validator_state_helper
                    .validator_voting_power
                    .get(&address)
                    .copied()
                    .unwrap_or_else(TendermintVotePower::zero);
                // sanity check, as multiple transactions/events may have cancelled out the vote power change
                if old_power != *new_power {
                    let old_key = (old_power, *address);
                    let node = self
                        .council_nodes_by_power
                        .remove(&old_key)
                        .unwrap_or_else(|| self.validator_state_helper.get_new_node(&address));

                    self.council_nodes_by_power
                        .insert((*new_power, *address), node);
                }
            }

            // for step 3
            let mut remaining_validators =
                self.validator_state_helper.validator_voting_power.clone();

            let mut new_to_track = Vec::new();
            let zero = TendermintVotePower::zero();
            // step 2: calculate updates for validators that are going to be in the validator set
            for ((voting_power, address), node) in self
                .council_nodes_by_power
                .iter()
                .rev()
                .take(max_validators)
            {
                let old_power = self
                    .validator_state_helper
                    .validator_voting_power
                    .get(&address);
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
                    self.validator_state_helper
                        .validator_voting_power
                        .insert(*address, *voting_power);
                    let validator_address: TendermintValidatorAddress =
                        node.consensus_pubkey.clone().into();
                    if !self.is_tracked(&validator_address) {
                        new_to_track.push((validator_address, *address));
                    }
                }
            }

            while let Some((validator_address, staking_address)) = new_to_track.pop() {
                self.add_validator_for_tracking(
                    validator_address,
                    staking_address,
                    block_signing_window,
                );
            }
            // step 3: calculate updates for validators that were removed from the validator set
            for (address, voting_power) in remaining_validators.iter() {
                let key = (*voting_power, *address);
                let alt_key = (zero, *address);
                let node = self
                    .council_nodes_by_power
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| self.council_nodes_by_power[&alt_key].clone());
                let mut validator = ValidatorUpdate::default();
                // even if voting_power > 0 (bonded amount >= minimal and not jailed),
                // it may have been < lowest stake/voting power
                // if the the number of current validators == max validators,
                // hence it's set to 0 in this update to be removed
                validator.set_power(0);
                validator.set_pub_key(get_validator_key(&node));
                validators.push(validator);
                self.validator_state_helper
                    .validator_voting_power
                    .remove(address);

                let validator_address: TendermintValidatorAddress =
                    node.consensus_pubkey.clone().into();
                self.remove_validator_from_tracking(&validator_address);

                // FIXME: if voting_power == 0, schedule removal from tendermint_validator_addresses +
                // council_nodes_by_power after unbonding period
            }
            self.validator_state_helper.clear();
            Some(validators)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::app_init::ValidatorState;
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::state::account::{CouncilNode, StakedState, StakedStateAddress};
    use chain_core::state::tendermint::TendermintValidatorPubKey;
    use std::collections::BTreeMap;

    fn get_initial_state() -> (
        ValidatorState,
        StakedStateAddress,
        TendermintValidatorPubKey,
        CouncilNode,
    ) {
        let v1_address: StakedStateAddress =
            StakedStateAddress::from(RedeemAddress::from([0u8; 20]));
        let v1_key = TendermintValidatorPubKey::Ed25519([0u8; 32]);
        let v1_node = CouncilNode::new(v1_key.clone());
        let v1_power = TendermintVotePower::from(Coin::one());
        let mut validator_by_voting_power = BTreeMap::new();
        validator_by_voting_power.insert((v1_power, v1_address), v1_node.clone());
        let mut validator_voting_power = BTreeMap::new();
        validator_voting_power.insert(v1_address, v1_power);

        let mut validator_state = ValidatorState::default();
        validator_state.council_nodes_by_power = validator_by_voting_power;
        validator_state
            .validator_state_helper
            .validator_voting_power = validator_voting_power;
        validator_state.add_validator_for_tracking(v1_key.clone().into(), v1_address, 10);
        (validator_state, v1_address, v1_key, v1_node)
    }

    fn add_node(
        address: [u8; 20],
        key: [u8; 32],
        power: Coin,
        validator_state: &mut ValidatorState,
    ) -> (CouncilNode, StakedStateAddress, TendermintValidatorAddress) {
        let v2_address: StakedStateAddress = StakedStateAddress::from(RedeemAddress::from(address));
        assert!(!validator_state
            .validator_state_helper
            .validator_voting_power
            .contains_key(&v2_address));
        let v2_key = TendermintValidatorPubKey::Ed25519(key);
        let v2_keyaddress = TendermintValidatorAddress::from(&v2_key);
        assert!(!validator_state.is_tracked(&v2_keyaddress));
        assert!(!validator_state.is_current_validator(&v2_keyaddress));
        let v2_node = CouncilNode::new(v2_key);

        validator_state
            .validator_state_helper
            .new_valid_node_join_update(&StakedState::new_init_bonded(
                power,
                0,
                v2_address,
                Some(v2_node.clone()),
            ));
        (v2_node, v2_address, v2_keyaddress)
    }

    fn contain_address(
        address: &StakedStateAddress,
        keyaddress: &TendermintValidatorAddress,
        validator_state: &ValidatorState,
    ) {
        assert!(validator_state
            .validator_state_helper
            .validator_voting_power
            .contains_key(address));
        assert!(validator_state.is_tracked(keyaddress));
        assert!(validator_state.is_current_validator(keyaddress));
    }

    fn not_contain_address(
        address: &StakedStateAddress,
        keyaddress: &TendermintValidatorAddress,
        validator_state: &ValidatorState,
    ) {
        assert!(!validator_state
            .validator_state_helper
            .validator_voting_power
            .contains_key(address));
        assert!(!validator_state.is_tracked(keyaddress));
    }

    #[test]
    fn new_nodes_should_be_added() {
        let (mut last_state, _, _, _) = get_initial_state();
        let (v2_node, v2_address, v2_keyaddress) =
            add_node([1u8; 20], [1u8; 32], Coin::one(), &mut last_state);

        let updates = last_state
            .get_validator_updates(1, 2)
            .expect("there are updates");
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].get_power(), 1);
        assert_eq!(*updates[0].get_pub_key(), get_validator_key(&v2_node));
        contain_address(&v2_address, &v2_keyaddress, &last_state);
    }

    #[test]
    fn nodes_with_lower_power_should_be_removed() {
        let (mut last_state, v1_address, v1_key, v1_node) = get_initial_state();
        let two = (Coin::one() + Coin::one()).unwrap();
        let (v2_node, v2_address, v2_keyaddress) =
            add_node([1u8; 20], [1u8; 32], two, &mut last_state);
        let (v3_node, v3_address, v3_keyaddress) =
            add_node([2u8; 20], [2u8; 32], two, &mut last_state);

        let updates = last_state
            .get_validator_updates(1, 2)
            .expect("there are updates");
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
            &last_state,
        );
        contain_address(&v2_address, &v2_keyaddress, &last_state);
        contain_address(&v3_address, &v3_keyaddress, &last_state);
    }

    #[test]
    fn nodes_with_0_power_should_be_removed() {
        let (mut last_state, v1_address, v1_key, v1_node) = get_initial_state();
        let (v2_node, v2_address, v2_keyaddress) =
            add_node([1u8; 20], [1u8; 32], Coin::one(), &mut last_state);
        last_state.validator_state_helper.punish_update(v1_address);

        let updates = last_state
            .get_validator_updates(1, 2)
            .expect("there are updates");

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
            &last_state,
        );
        contain_address(&v2_address, &v2_keyaddress, &last_state);
    }
}
